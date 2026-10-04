import json
import logging
import os
import re
from pathlib import Path

from harness import proc
from harness.scanners.findings import extract_cwe, make_finding

log = logging.getLogger(__name__)

SEVERITY = {"CRITICAL": "critical", "ERROR": "high", "HIGH": "high",
            "WARNING": "medium", "MEDIUM": "medium", "INFO": "low", "LOW": "low"}
MAX_ARGS_CHARS = 100_000
# For rules marked `harness-sql-text`, the matched code itself must look like SQL. Semgrep cannot
# test a template literal's text, so a rule for "string built from variables" would otherwise
# also match every `className={`...${x}`}`.
SQL_TEXT = re.compile(
    r"(?is)\bselect\s+(distinct\s+)?[\w*.,\s\"`()]+?\s+from\s+[\w.\"`\[\]]"   # SELECT cols FROM table
    r"|\binsert\s+into\s+[\w.\"`\[\]]"
    r"|\bupdate\s+[\w.\"`\[\]]+\s+set\s+\w"
    r"|\bdelete\s+from\s+[\w.\"`\[\]]"
    r"|\bwhere\s+[\w.\"`]+\s*(=|<|>|\blike\b|\bin\s*\()")


def _matched_text(code_dir, r, cache):
    path = r["path"]
    if path not in cache:
        try:
            cache[path] = (Path(code_dir) / path).read_bytes()
        except OSError:
            cache[path] = b""
    return cache[path][r["start"].get("offset", 0):r["end"].get("offset", 0)].decode(errors="replace")


def _rule_prefixes(configs):
    """Semgrep prefixes ids of rules from a local file with the file's folder, dotted."""
    out = []
    for c in configs:
        p = Path(c)
        folder = p if p.is_dir() else p.parent
        out.append(".".join(folder.resolve().parts[1:]) + ".")
    return out


def _clean_rule_id(check_id, prefixes):
    for pre in prefixes:
        if check_id.startswith(pre):
            return check_id[len(pre):]
    return check_id


def _title(rule_id):
    return rule_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ").capitalize()


def _chunks(files):
    batch, size = [], 0
    for f in files:
        if batch and size + len(f) > MAX_ARGS_CHARS:
            yield batch
            batch, size = [], 0
        batch.append(f)
        size += len(f) + 1
    if batch:
        yield batch


async def scan(code_dir, files, configs, raw_dir, procs=None):
    """Run Semgrep on the given relative file paths (explicit targets, so Semgrep's
    default ignore list does not hide test folders). Returns findings."""
    # Semgrep runs inside code_dir, so local rule paths must be absolute.
    configs = [str(Path(c).resolve()) if Path(c).exists() else c for c in configs]
    results, errors = [], []
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    args = ["semgrep", "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
    for c in configs:
        args += ["--config", c]
    for batch in _chunks(sorted(files)):
        rc, out, err = await proc.run(args + ["--"] + batch, cwd=code_dir, procs=procs, env=env)
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            raise proc.CommandError(f"semgrep failed (exit {rc}): {err.strip()[-300:]}")
        results += data.get("results", [])
        errors += data.get("errors", [])
    Path(raw_dir, "semgrep.json").write_text(json.dumps({"results": results, "errors": errors}))
    if errors:
        log.info("semgrep reported %d non-fatal errors", len(errors))

    prefixes = _rule_prefixes(configs)
    findings, seen, texts = [], set(), {}
    for r in results:
        meta = r.get("extra", {}).get("metadata") or {}
        if meta.get("harness-sql-text") and not SQL_TEXT.search(_matched_text(code_dir, r, texts)):
            continue
        # One rule can match nested parts of one expression; keep one finding per rule and line.
        key = (r["check_id"], r["path"], r["start"]["line"])
        if key in seen:
            continue
        seen.add(key)
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        rule_id = _clean_rule_id(r["check_id"], prefixes)
        f = make_finding(
            "semgrep", rule_id, _title(rule_id),
            SEVERITY.get(str(extra.get("severity", "")).upper(), "low"),
            extract_cwe(meta.get("cwe")), r["path"],
            r["start"]["line"], r["end"]["line"], r["start"].get("col"), r["end"].get("col"),
            extra.get("message", ""), code_dir)
        # Secret rules point straight at the value; mark them so snippets get masked.
        f["_secret"] = ".secrets." in f".{rule_id}."
        findings.append(f)
    return findings
