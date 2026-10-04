"""SonarQube: run the scanner CLI, wait for the server, then read issues and hotspots."""

import asyncio
import base64
import json
import logging
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from harness import proc
from harness.scanners.findings import extract_cwe, make_finding

log = logging.getLogger(__name__)

SEVERITY = {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium", "MINOR": "low", "INFO": "info",
            # Newer "impact" severities
            "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
CE_POLL_SECONDS = 2
CE_TIMEOUT_SECONDS = 1800
PAGE = 500


class SonarError(Exception):
    pass


def project_key(session_id):
    return f"harness-{session_id}"


class SonarClient:
    def __init__(self, host_url, token, timeout=60):
        self.host_url = host_url.rstrip("/")
        self.timeout = timeout
        self._auth = "Basic " + base64.b64encode(f"{token}:".encode()).decode()

    def _request(self, method, path, params):
        url = f"{self.host_url}{path}"
        data = None
        if method == "GET":
            url += "?" + urllib.parse.urlencode(params)
        else:
            data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data, method=method, headers={"Authorization": self._auth})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read()
        except urllib.error.HTTPError as e:
            raise SonarError(f"SonarQube {path} returned HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise SonarError(f"SonarQube cannot be reached at {self.host_url}") from e
        return json.loads(body) if body else {}

    async def get(self, path, **params):
        return await asyncio.to_thread(self._request, "GET", path, params)

    async def post(self, path, **params):
        return await asyncio.to_thread(self._request, "POST", path, params)

    async def paged(self, path, key, **params):
        items, page = [], 1
        while True:
            data = await self.get(path, ps=PAGE, p=page, **params)
            batch = data.get(key, [])
            items += batch
            total = data.get("paging", {}).get("total", data.get("total", len(items)))
            if not batch or len(items) >= total or page * PAGE >= 10_000:
                return items
            page += 1

    async def delete_project(self, key):
        try:
            await self.post("/api/projects/delete", project=key)
        except SonarError as e:
            log.warning("could not delete SonarQube project %s: %s", key, e)


def _issue_severity(issue):
    if issue.get("severity") in SEVERITY:
        return SEVERITY[issue["severity"]]
    impacts = [SEVERITY.get(i.get("severity"), "low") for i in issue.get("impacts", [])]
    order = ["critical", "high", "medium", "low", "info"]
    return min(impacts, key=order.index) if impacts else "medium"


async def _rule_info(client, rule_key, cache):
    """Name and CWE for a rule, looked up once per scan. Newer SonarQube versions leave
    securityStandards out of /api/rules/show, so the CWE comes from the search API's cwe facet."""
    if rule_key not in cache:
        name, cwe = rule_key, None
        try:
            data = await client.get("/api/rules/search", rule_key=rule_key, facets="cwe", f="name", ps=1)
            rules = data.get("rules") or []
            name = rules[0].get("name", rule_key) if rules else rule_key
            vals = [v["val"] for f in data.get("facets", []) if f.get("property") == "cwe"
                    for v in f.get("values", []) if v.get("count") and str(v.get("val")).isdigit()]
            cwe = f"CWE-{vals[0]}" if vals else None
        except SonarError:
            pass
        cache[rule_key] = (name, cwe)
    return cache[rule_key]


def _path(component, key):
    return component.split(":", 1)[1] if component.startswith(key + ":") else None


async def scan(code_dir, session_id, cfg, raw_dir, procs=None, client=None, inclusions=None):
    """Analyse the folder (or only `inclusions`, a list of sonar.inclusions patterns) and return findings."""
    client = client or SonarClient(cfg.sonar_host_url, cfg.sonar_token)
    key = project_key(session_id)
    status = (await client.get("/api/system/status")).get("status")
    if status and status != "UP":
        raise SonarError(f"SonarQube is not ready (status {status})")
    with tempfile.TemporaryDirectory() as work:
        empty = Path(work, "empty-binaries")
        empty.mkdir()
        rc, out, err = await proc.run([
            "sonar-scanner",
            f"-Dsonar.projectKey={key}",
            f"-Dsonar.projectName={key}",
            "-Dsonar.sources=.",
            f"-Dsonar.host.url={cfg.sonar_host_url}",
            f"-Dsonar.working.directory={work}/scannerwork",
            "-Dsonar.scm.disabled=true",
            # Java projects without compiled classes: point at an empty folder so the scan does not fail.
            f"-Dsonar.java.binaries={empty}",
            "-Dsonar.qualitygate.wait=false",
            *([f"-Dsonar.inclusions={','.join(inclusions)}"] if inclusions else []),
        ], cwd=code_dir, procs=procs, env={**os.environ, "SONAR_TOKEN": cfg.sonar_token})
        if rc != 0:
            tail = "\n".join(l for l in (out + err).splitlines() if "ERROR" in l)[-400:]
            raise SonarError(f"sonar-scanner failed (exit {rc}): {tail.replace(cfg.sonar_token, '***')}")
        task_file = Path(work, "scannerwork", "report-task.txt")
        props = dict(l.split("=", 1) for l in task_file.read_text().splitlines() if "=" in l)

    task_id = props.get("ceTaskId")
    for _ in range(CE_TIMEOUT_SECONDS // CE_POLL_SECONDS):
        status = (await client.get("/api/ce/task", id=task_id))["task"]["status"]
        if status == "SUCCESS":
            break
        if status in ("FAILED", "CANCELED"):
            raise SonarError(f"SonarQube analysis {status.lower()}")
        await asyncio.sleep(CE_POLL_SECONDS)
    else:
        raise SonarError("SonarQube analysis timed out")

    issues = await client.paged("/api/issues/search", "issues", components=key,
                                types=",".join(cfg.sonar_issue_types), resolved="false")
    hotspots = await client.paged("/api/hotspots/search", "hotspots", projectKey=key)
    Path(raw_dir, "sonarqube.json").write_text(json.dumps({"issues": issues, "hotspots": hotspots}))
    return await to_findings(issues, hotspots, key, client, code_dir)


async def to_findings(issues, hotspots, key, client, code_dir):
    cache, findings = {}, []
    for item, is_hotspot in [(i, False) for i in issues] + [(h, True) for h in hotspots]:
        path = _path(item.get("component", ""), key)
        rng = item.get("textRange")
        if not path or not rng:
            continue
        rule = item.get("ruleKey") if is_hotspot else item.get("rule")
        name, cwe = await _rule_info(client, rule, cache)
        if is_hotspot:
            sev = "high" if item.get("vulnerabilityProbability") == "HIGH" else "medium"
        else:
            sev = _issue_severity(item)
        sc, ec = rng.get("startOffset"), rng.get("endOffset")
        findings.append(make_finding(
            "sonarqube", rule, name, sev, cwe, path, rng["startLine"], rng.get("endLine"),
            sc + 1 if sc is not None else None, ec if ec is not None else None,
            item.get("message", ""), code_dir))
    return findings
