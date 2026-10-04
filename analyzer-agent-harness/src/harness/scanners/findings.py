"""The finding format from the contract, and helpers shared by every scanner."""

import hashlib
import re
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
TOOLS = ["semgrep", "gitleaks", "sonarqube"]
SNIPPET_CONTEXT = 5


def severity_rank(sev):
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def read_lines(path):
    try:
        return Path(path).read_text(errors="replace").splitlines()
    except OSError:
        return []


def finding_id(tool, rule_id, path, line_text):
    raw = "\x00".join([tool, rule_id, path, line_text.strip()])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def extract_cwe(value):
    """Find the first CWE-<n> in a string or a list of strings."""
    if isinstance(value, (list, tuple)):
        value = " ".join(map(str, value))
    m = re.search(r"cwe[-:\s]*(\d+)", str(value or ""), re.IGNORECASE)
    return f"CWE-{m.group(1)}" if m else None


def mask_value(value):
    return value[:4] + "*" * max(len(value) - 4, 4)


def mask_lines(lines, first_line_no, spans):
    """Mask secret spans in a list of lines that starts at line `first_line_no`.
    `spans` holds (start_line, start_col, end_line, end_col), 1-based, inclusive.
    A missing column means the whole line."""
    out = list(lines)
    for start_line, start_col, end_line, end_col in spans:
        for line_no in range(start_line, end_line + 1):
            i = line_no - first_line_no
            if not 0 <= i < len(out):
                continue
            text = out[i]
            s = (start_col or 1) - 1 if line_no == start_line else 0
            e = min(end_col or len(text), len(text)) if line_no == end_line else len(text)
            if s < e:
                out[i] = text[:s] + mask_value(text[s:e]) + text[e:]
    return out


def make_finding(tool, rule_id, title, severity, cwe, path, start_line, end_line,
                 start_col, end_col, message, code_dir):
    """Build a contract finding (LLM fields empty) from one scanner result."""
    full = Path(code_dir) / path
    lines = read_lines(full)
    start_line = max(int(start_line or 1), 1)
    end_line = max(int(end_line or start_line), start_line)
    line_text = lines[start_line - 1] if start_line <= len(lines) else ""
    return {
        "id": finding_id(tool, rule_id, path, line_text),
        "tools": [tool],
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "cwe": cwe,
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "start_col": start_col,
        "end_col": end_col,
        "file_sha256": file_sha256(full) if full.is_file() else "",
        "message": message,
        "snippet": "",
        "verdict": "unsure",
        "explanation": "",
        "fix_recommendation": "",
        "suggested_patch": None,
        "status": "new",
        "web_url": None,
    }


def secret_spans(findings):
    """Secret locations per path, from findings that point at a secret value."""
    spans = {}
    for f in findings:
        if f.get("_secret"):
            spans.setdefault(f["path"], []).append(
                (f["start_line"], f["start_col"], f["end_line"], f["end_col"]))
    return spans


def add_snippets(findings, code_dir):
    """Fill `snippet` with lines around each finding, with every known secret masked."""
    spans = secret_spans(findings)
    cache = {}
    for f in findings:
        if f["path"] not in cache:
            cache[f["path"]] = read_lines(Path(code_dir) / f["path"])
        lines = cache[f["path"]]
        first = max(f["start_line"] - SNIPPET_CONTEXT, 1)
        last = min(f["end_line"] + SNIPPET_CONTEXT, len(lines))
        f["_mask"] = spans.get(f["path"], [])
        f["snippet"] = "\n".join(mask_lines(lines[first - 1:last], first, f["_mask"]))


def dedupe_ids(findings):
    """Two findings can share an id (same rule on two identical lines). Make ids unique
    by adding an occurrence number, in line order, so they stay stable across scans."""
    seen = {}
    for f in sorted(findings, key=lambda f: (f["path"], f["start_line"])):
        n = seen.get(f["id"], 0)
        seen[f["id"]] = n + 1
        if n:
            f["id"] = hashlib.sha256(f"{f['id']}#{n}".encode()).hexdigest()[:32]
    return findings


def public(finding):
    """The finding without internal keys (those starting with _)."""
    return {k: v for k, v in finding.items() if not k.startswith("_")}
