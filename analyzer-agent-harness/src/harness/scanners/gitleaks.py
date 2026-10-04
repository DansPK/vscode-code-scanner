import json
import logging
from pathlib import Path

from harness import proc
from harness.scanners.findings import make_finding

log = logging.getLogger(__name__)


async def scan(code_dir, files, raw_dir, procs=None):
    """Run Gitleaks in directory mode with redaction. Gitleaks takes one folder, so it
    scans the whole folder; results are then limited to `files` (relative paths)."""
    report = Path(raw_dir, "gitleaks.json")
    rc, out, err = await proc.run(
        ["gitleaks", "dir", ".", "--report-format", "json", "--report-path", str(report.resolve()),
         "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"],
        cwd=code_dir, procs=procs)
    if rc != 0 or not report.exists():
        raise proc.CommandError(f"gitleaks failed (exit {rc})")
    wanted = set(files)
    findings = []
    for r in json.loads(report.read_text() or "[]"):
        path = r["File"].removeprefix("./")
        if path not in wanted:
            continue
        f = make_finding(
            "gitleaks", r["RuleID"], r.get("Description") or r["RuleID"], "high", "CWE-798",
            path, r["StartLine"], r["EndLine"], r.get("StartColumn"), r.get("EndColumn"),
            f"Possible secret found: {r.get('Description') or r['RuleID']}", code_dir)
        f["_secret"] = True
        if f["start_col"]:
            # Gitleaks columns can be one off; widen by one so the whole value is masked.
            f["start_col"] = max(f["start_col"] - 1, 1)
        findings.append(f)
    return findings
