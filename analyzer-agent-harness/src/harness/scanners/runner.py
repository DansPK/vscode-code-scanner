"""Run the three scanners side by side and produce merged contract findings."""

import asyncio
import logging
from pathlib import Path

from harness.scanners import gitleaks, merge, semgrep, sonarqube
from harness.scanners.findings import add_snippets, dedupe_ids

log = logging.getLogger(__name__)


async def run_tools(code_dir, files, session_id, cfg, raw_dir, procs=None, on_done=None, sonar_client=None):
    """Scan `files` (relative paths) in `code_dir`. SonarQube always scans the whole folder.
    Returns (unmerged findings, errors) where errors maps tool name to a short message.
    A failing tool does not stop the others. `on_done(tool, findings_or_None)` is awaited per tool,
    so callers can show results while the other tools still run."""
    Path(raw_dir).mkdir(parents=True, exist_ok=True)
    jobs = {"sonarqube": sonarqube.scan(code_dir, session_id, cfg, raw_dir, procs, client=sonar_client)}
    if files:  # nothing changed: only SonarQube (which has no partial scan) runs
        jobs = {"semgrep": semgrep.scan(code_dir, files, cfg.semgrep_configs, raw_dir, procs),
                "gitleaks": gitleaks.scan(code_dir, files, raw_dir, procs), **jobs}

    async def one(tool, job):
        try:
            result = await job
        except asyncio.CancelledError:
            raise
        except Exception as e:  # one tool failing must not stop the others
            log.warning("%s failed: %s", tool, e)
            if on_done:
                await on_done(tool, None)
            return tool, e
        if on_done:
            await on_done(tool, result)
        return tool, result

    findings, errors = [], {}
    for tool, result in await asyncio.gather(*(one(t, j) for t, j in jobs.items())):
        if isinstance(result, Exception):
            errors[tool] = str(result) or type(result).__name__
        else:
            findings += result
    return findings, errors


def finalize(findings, code_dir):
    """Snippets, then merge, then unique ids. Snippets come before merging,
    so every tool's secret location gets masked."""
    add_snippets(findings, code_dir)
    return dedupe_ids(merge.merge(findings))


async def run_all(code_dir, files, session_id, cfg, raw_dir, **kw):
    findings, errors = await run_tools(code_dir, files, session_id, cfg, raw_dir, **kw)
    return finalize(findings, code_dir), errors
