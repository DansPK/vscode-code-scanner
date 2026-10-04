"""Background scans: the pipeline, progress state, cancel, and the scan summary."""

import asyncio
import errno
import json
import logging
import secrets
from collections import Counter
from pathlib import Path

from harness import llm as llm_mod
from harness import logs
from harness.db import now
from harness.scanners import runner
from harness.scanners.findings import SEVERITIES, TOOLS

log = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 10
TOOL_NAMES = {"semgrep": "Semgrep", "gitleaks": "Gitleaks", "sonarqube": "SonarQube"}


class ScanError(Exception):
    pass


class Running:
    def __init__(self, scan_id, session_id):
        self.scan_id = scan_id
        self.session_id = session_id
        self.task = None
        self.procs = set()
        self.message = "Queued"
        self.version = 0
        self.changed = asyncio.Condition()


def summary(row):
    return {
        "scan_id": row["id"], "session_id": row["session_id"], "status": row["status"],
        "stage": row["stage"], "percent": row["percent"], "counts": json.loads(row["counts"]),
        "error": row["error"], "started_at": row["started_at"], "finished_at": row["finished_at"],
    }


class ScanManager:
    def __init__(self, cfg, db, llm, sonar_client=None):
        self.cfg = cfg
        self.db = db
        self.llm = llm
        self.sonar_client = sonar_client
        self.running = {}  # scan_id -> Running

    def recover(self):
        """Scans that were running when the server stopped cannot finish."""
        n = self.db.run("UPDATE scans SET status='failed', error='The server restarted during the scan.', "
                        "finished_at=? WHERE status IN ('queued','running')", (now(),))
        if n:
            log.info("marked %d interrupted scans as failed", n)

    def is_running(self, session_id):
        return any(r.session_id == session_id for r in self.running.values()) or bool(
            self.db.one("SELECT 1 FROM scans WHERE session_id=? AND status IN ('queued','running')", (session_id,)))

    def scan_dir(self, session_id, scan_id):
        return self.cfg.sessions_dir / session_id / "scans" / scan_id

    def latest_done(self, session_id):
        return self.db.one("SELECT * FROM scans WHERE session_id=? AND status='done' "
                           "ORDER BY created_at DESC, rowid DESC LIMIT 1", (session_id,))

    def start(self, session, plan):
        """`plan`: {"files": all manifest paths, "changed": set, "full": bool, "web_base": str|None,
        "paths": list of path prefixes to limit the scan to ([] = everything)}."""
        scan_id = secrets.token_hex(12)
        self.db.run("INSERT INTO scans (id, session_id, status, stage, percent, created_at) "
                    "VALUES (?,?,'queued','preparing',0,?)", (scan_id, session["id"], now()))
        run = Running(scan_id, session["id"])
        self.running[scan_id] = run
        run.task = asyncio.create_task(self._run(run, session, plan))
        return scan_id

    async def _update(self, run, message=None, **fields):
        if message:
            fields["message"] = message
        if fields:
            cols = ", ".join(f"{k}=?" for k in fields)
            self.db.run(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), run.scan_id))
        if message:
            run.message = message
        async with run.changed:
            run.version += 1
            run.changed.notify_all()

    async def _run(self, run, session, plan):
        sid = session["id"]
        logs.bind(session=sid, scan=run.scan_id)
        code_dir = self.cfg.sessions_dir / sid / "code"
        raw_dir = self.scan_dir(sid, run.scan_id) / "raw"
        try:
            await self._update(run, "Preparing the scan", status="running", stage="preparing", percent=2,
                               started_at=now())
            prev = self.latest_done(sid)
            scope = plan.get("paths") or []
            in_scope = _scope_test(scope)
            # Files to run Semgrep and Gitleaks on: in scope, and changed unless this is a full scan.
            targets = sorted(p for p in plan["files"]
                             if in_scope(p) and (plan["full"] or prev is None or p in plan["changed"]))
            remaining = [t for t in TOOLS if targets or t == "sonarqube"]
            started = len(remaining)
            where = f" in {', '.join(scope)}" if scope else ""
            await self._update(run, f"Scanning {len(targets)} files{where}", stage=remaining[0], percent=5)

            before = {r["id"] for r in self.db.all("SELECT id FROM findings WHERE scan_id=?", (prev["id"],))} \
                if prev else set()
            carried = self._carry_over(prev, plan, {}, in_scope) if prev else []
            partial = list(carried)

            def publish(raw_list):
                """Merge what we have so far and store it, so the client sees findings while the scan runs."""
                found = runner.finalize([dict(f) for f in raw_list], code_dir)
                for f in found:
                    f["status"] = "existing" if f["id"] in before else "new"
                    if plan.get("web_base"):
                        f["web_url"] = f"{plan['web_base']}/{f['path']}#L{f['start_line']}-L{f['end_line']}"
                    cached = self.db.get_review(f["id"], f["file_sha256"])
                    if cached:
                        f.update(cached)
                self.db.save_findings(run.scan_id, sid, found, replace=True)
                return found

            async def on_done(tool, result):
                remaining.remove(tool)
                pct = 5 + 55 * (started - len(remaining)) // started
                if result is None:
                    text = f"{TOOL_NAMES[tool]} failed"
                else:
                    partial.extend(result)
                    shown = await asyncio.to_thread(publish, partial)
                    text = f"{TOOL_NAMES[tool]}: {len(result)} findings ({len(shown)} so far)"
                await self._update(run, text, stage=remaining[0] if remaining else "merging", percent=pct)

            unchanged = prev is not None and not plan["full"] and not targets
            if unchanged:
                # Nothing changed: keep every earlier finding instead of rescanning.
                await self._update(run, "No files changed since the last scan; keeping its findings",
                                   stage="merging", percent=60)
                raw, errors = self._carry_over(prev, plan, {"sonarqube": "not run"}, in_scope), {}
            else:
                if carried:
                    await asyncio.to_thread(publish, carried)
                raw, errors = await runner.run_tools(code_dir, targets, sid, self.cfg, raw_dir, run.procs,
                                                     on_done, self.sonar_client,
                                                     sonar_inclusions=_sonar_inclusions(scope, plan["files"]))
                await self._update(run, "Merging results", stage="merging", percent=60)
                if prev:
                    raw += self._carry_over(prev, plan, errors, in_scope)
            raw_dir.mkdir(parents=True, exist_ok=True)
            Path(raw_dir, "tool_findings.json").write_text(json.dumps(raw))
            findings = runner.finalize(raw, code_dir)
            for f in findings:
                f["status"] = "existing" if f["id"] in before else "new"
                if plan.get("web_base"):
                    f["web_url"] = f"{plan['web_base']}/{f['path']}#L{f['start_line']}-L{f['end_line']}"
            # Store the full list before the slow LLM step; reviews then fill in one by one.
            for f in findings:
                cached = self.db.get_review(f["id"], f["file_sha256"])
                if cached:
                    f.update(cached)
            self.db.save_findings(run.scan_id, sid, findings, replace=True)

            await self._update(run, f"Reviewing {len(findings)} findings", stage="llm_review", percent=65)

            async def on_review(done, total, finding):
                self.db.update_finding(run.scan_id, finding)
                await self._update(run, f"LLM review: {done} of {total} new findings",
                                   percent=65 + int(34 * done / max(total, 1)))

            _, llm_error = await llm_mod.review_findings(findings, code_dir, self.llm, self.db,
                                                         self.cfg.llm_max_parallel, on_review)
            if llm_error:
                errors["llm"] = llm_error

            self.db.save_findings(run.scan_id, sid, findings, replace=True)
            counts = Counter(f["severity"] for f in findings)
            error = "; ".join(f"{k}: {v}" for k, v in errors.items()) or None
            done_text = (f"No files changed since the last scan; {len(findings)} findings kept" if unchanged
                         else f"Done: {len(findings)} findings")
            await self._update(run, done_text, status="done", stage="finished", percent=100,
                               counts=json.dumps({s: counts.get(s, 0) for s in SEVERITIES}),
                               error=error, finished_at=now())
        except asyncio.CancelledError:
            await self._update(run, "Cancelled", status="cancelled", finished_at=now())
        except Exception as e:
            log.exception("scan %s failed", run.scan_id)
            await self._update(run, "Failed", status="failed", error=_short_error(e), finished_at=now())
        finally:
            self.db.run("UPDATE sessions SET updated_at=? WHERE id=?", (now(), sid))
            self.running.pop(run.scan_id, None)
            async with run.changed:
                run.version += 1
                run.changed.notify_all()

    def _carry_over(self, prev, plan, errors, in_scope):
        """Earlier per-tool findings to keep:
        - everything for files outside the scan's scope (a folder scan leaves the rest alone);
        - in scope, unless this is a full scan: Semgrep and Gitleaks results for unchanged files
          (only changed files were rescanned), and SonarQube's only if it failed this time."""
        path = self.scan_dir(prev["session_id"], prev["id"]) / "raw" / "tool_findings.json"
        if not path.exists():
            return []
        present = set(plan["files"])
        keep = []
        for f in json.loads(path.read_text()):
            if f["path"] not in present:
                continue
            if not in_scope(f["path"]):
                keep.append(f)
            elif not plan["full"] and f["path"] not in plan["changed"] and (
                    f["tools"][0] != "sonarqube" or "sonarqube" in errors):
                keep.append(f)
        return keep

    def status(self, scan_id):
        row = self.db.one("SELECT * FROM scans WHERE id=?", (scan_id,))
        return summary(row) if row else None

    async def watch(self, scan_id, report):
        """Call `report(percent, message)` on each change, and at least every HEARTBEAT_SECONDS,
        until the scan ends. Returns the final summary."""
        run = self.running.get(scan_id)
        while run is not None and run.task is not None and not run.task.done():
            row = self.status(scan_id)
            await report(row["percent"], f"{run.message}")
            seen = run.version
            async with run.changed:
                try:
                    await asyncio.wait_for(run.changed.wait_for(lambda: run.version != seen), HEARTBEAT_SECONDS)
                except asyncio.TimeoutError:
                    pass
        final = self.status(scan_id)
        row = self.db.one("SELECT message FROM scans WHERE id=?", (scan_id,))
        await report(final["percent"], row["message"] or final["status"].capitalize())
        return final

    async def cancel(self, scan_id):
        run = self.running.get(scan_id)
        if run is None or run.task is None:
            return False
        run.task.cancel()
        try:
            await run.task
        except asyncio.CancelledError:
            pass
        return True

    async def cancel_session(self, session_id):
        for run in list(self.running.values()):
            if run.session_id == session_id:
                await self.cancel(run.scan_id)


def _scope_test(scope):
    """A test for "is this path inside the scan's scope". Scope entries are files or folders."""
    if not scope:
        return lambda p: True
    return lambda p: any(p == s or p.startswith(s + "/") for s in scope)


def _sonar_inclusions(scope, files):
    """sonar.inclusions patterns for a scoped scan, or None for everything."""
    if not scope:
        return None
    present = set(files)
    return [s if s in present else f"{s}/**" for s in scope]


def _short_error(e):
    if isinstance(e, OSError) and e.errno == errno.ENOSPC:
        return "The server disk is full."
    msg = str(e).strip() or type(e).__name__
    return msg.splitlines()[0][:300]
