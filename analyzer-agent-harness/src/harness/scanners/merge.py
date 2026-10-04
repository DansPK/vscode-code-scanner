"""Merge findings from different tools that describe the same problem."""

from difflib import SequenceMatcher

from harness.scanners.findings import TOOLS, severity_rank

TITLE_SIMILARITY = 0.6


def _same_problem(a, b):
    if a["path"] != b["path"]:
        return False
    if a["start_line"] > b["end_line"] or b["start_line"] > a["end_line"]:
        return False
    if a["cwe"] or b["cwe"]:
        return a["cwe"] == b["cwe"]
    return SequenceMatcher(None, a["title"].lower(), b["title"].lower()).ratio() >= TITLE_SIMILARITY


def _same_tool_duplicate(a, b):
    """Several rules of one tool often report one problem on one line (e.g. three Semgrep
    command-injection rules). Those merge only on the same start line with the same CWE."""
    return a["path"] == b["path"] and a["start_line"] == b["start_line"] and a["cwe"] and a["cwe"] == b["cwe"]


def merge(findings):
    """Keep one finding per problem: list every tool, keep the highest severity.
    The kept finding is the first by (tool order, path, line, rule), so its id and rule_id stay stable."""
    ordered = sorted(findings, key=lambda f: (TOOLS.index(f["tools"][0]), f["path"], f["start_line"], f["rule_id"]))
    kept = []
    for f in ordered:
        tool = f["tools"][0]
        match = next((k for k in kept if (tool not in k["tools"] and _same_problem(k, f))
                      or (tool in k["tools"] and _same_tool_duplicate(k, f))), None)
        if match is None:
            kept.append(dict(f, tools=list(f["tools"])))
            continue
        if tool not in match["tools"]:
            match["tools"].append(tool)
        if severity_rank(f["severity"]) < severity_rank(match["severity"]):
            match["severity"] = f["severity"]
    return kept
