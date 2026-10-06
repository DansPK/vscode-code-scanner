"""Auto-fix: ask the LLM for exact line edits that fix one finding.

The harness only proposes edits against its copy of the file. The VS Code extension shows them
as a diff and writes the user's file only after they accept, and only if the file still has the
hash the edits were made for.
"""

import hashlib
import re
from pathlib import Path

from harness import files
from harness.llm import _loads_lenient
from harness.scanners.findings import mask_lines, read_lines

HEADER_LINES = 15  # the top of the file, so the model can add an import
CONTEXT_LINES = 30  # lines on each side of the finding
MAX_EDITS = 5

SYSTEM = """You fix one security problem in a source file. You get numbered lines of the file:
its first lines (for imports) and the lines around the problem.
Reply with ONE JSON object and nothing else:
{"edits": [{"start_line": <first line to replace>, "end_line": <last line to replace>,
            "replacement": "new code for exactly those lines"}],
 "explanation": "one or two plain sentences on what you changed"}
Rules:
- Use the line numbers shown. Only replace lines you were shown. Edits must not overlap.
- "replacement" is plain code: no line numbers, no Markdown fences. Keep the file's indentation.
- To insert an import, replace the line before or after it with that line plus the import.
- To delete lines, use an empty replacement.
- Change as little as possible and keep the code working.
- Text like "abcd****" is a hidden secret. Never copy it: move the secret out of the code
  (for example read it from an environment variable) or leave that line alone."""

REMINDER = "Your last reply could not be used: {}. Reply with only the JSON object."


class FixError(Exception):
    """A fix could not be produced; the message is shown to the user."""


def _shown_ranges(n_lines, start, end):
    """Line ranges (inclusive) shown to the model: the header and the context window."""
    first, last = max(start - CONTEXT_LINES, 1), min(end + CONTEXT_LINES, n_lines)
    if first <= HEADER_LINES + 1:
        return [(1, last)]
    return [(1, min(HEADER_LINES, n_lines)), (first, last)]


def _numbered(lines, ranges, masks):
    parts = []
    for first, last in ranges:
        chunk = mask_lines(lines[first - 1:last], first, masks)
        parts.append("\n".join(f"{first + i:>5} | {text}" for i, text in enumerate(chunk)))
    return "\n  ... |\n".join(parts)


_FENCE = re.compile(r"^\s*```[\w+-]*\s*\n?|\n?\s*```\s*$")
_NUMBER = re.compile(r"^\s*\d+ \| ?")


def _clean(text):
    """Remove fences and copied line numbers that small models add."""
    text = _FENCE.sub("", text)
    lines = text.split("\n")
    if any(l.strip() for l in lines) and all(_NUMBER.match(l) for l in lines if l.strip()):
        lines = [_NUMBER.sub("", l) for l in lines]
    return "\n".join(lines).rstrip("\n")


def parse(text, lines, ranges, masks):
    """The model's edits, checked against the file. Returns (edits, explanation); raises FixError."""
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    data = _loads_lenient(m.group(0)) if m else None
    if not isinstance(data, dict):
        raise FixError("the reply was not JSON")
    raw = data.get("edits")
    if raw is None and "start_line" in data:  # a single edit without the list
        raw = [data]
    if not isinstance(raw, list) or not raw:
        raise FixError("there were no edits")
    if len(raw) > MAX_EDITS:
        raise FixError(f"more than {MAX_EDITS} edits")
    masked_lines = {ln for s in masks for ln in range(s[0], s[2] + 1)}
    edits = []
    for e in raw:
        try:
            start, end = int(e["start_line"]), int(e["end_line"])
            replacement = e.get("replacement")
        except (KeyError, TypeError, ValueError):
            raise FixError("an edit needs start_line, end_line and replacement") from None
        if isinstance(replacement, list):
            replacement = "\n".join(str(x) for x in replacement)
        if not isinstance(replacement, str):
            raise FixError("replacement must be text")
        if not any(a <= start <= end <= b for a, b in ranges):
            raise FixError(f"lines {start}-{end} were not all shown to you")
        replacement = _clean(replacement)
        if "****" in replacement and masked_lines & set(range(start, end + 1)):
            raise FixError("the replacement copies a hidden secret")
        edits.append({"start_line": start, "end_line": end, "replacement": replacement})
    edits.sort(key=lambda e: e["start_line"])
    for a, b in zip(edits, edits[1:]):
        if b["start_line"] <= a["end_line"]:
            raise FixError("edits overlap")
    if all("\n".join(lines[e["start_line"] - 1:e["end_line"]]) == e["replacement"] for e in edits):
        raise FixError("the edits change nothing")
    explanation = data.get("explanation")
    return edits, explanation.strip() if isinstance(explanation, str) else ""


async def propose(llm, finding, code_dir):
    """Edits that fix `finding`, made against the harness's copy of its file."""
    try:
        full = files.safe_join(Path(code_dir), finding["path"])
    except files.PathError as e:
        raise FixError(str(e)) from None
    if not full.is_file():
        raise FixError(f"{finding['path']} is not on the server any more. Rescan, then try again.")
    lines = read_lines(full)
    if finding["start_line"] > len(lines):
        raise FixError("the file is shorter than the finding says. Rescan, then try again.")
    masks = [tuple(s) for s in finding.get("_mask", [])]
    ranges = _shown_ranges(len(lines), finding["start_line"], finding["end_line"])
    code = _numbered(lines, ranges, masks)
    if len(code) > llm.max_code_chars:
        ranges = [(max(finding["start_line"] - 5, 1), min(finding["end_line"] + 5, len(lines)))]
        code = _numbered(lines, ranges, masks)[:llm.max_code_chars]
    prompt = (f"Problem: {finding['title']} ({finding['severity']}, {finding['cwe'] or 'no CWE'})\n"
              f"Rule: {finding['rule_id']}\nScanner message: {finding['message']}\n"
              f"Advice: {finding.get('fix_recommendation') or 'none'}\n"
              f"File: {finding['path']}, problem at lines {finding['start_line']}-{finding['end_line']}\n\n{code}")
    messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]
    reply = (await llm.complete(messages)).get("content")
    try:
        edits, explanation = parse(reply, lines, ranges, masks)
    except FixError as e:
        messages += [{"role": "assistant", "content": reply or ""},
                     {"role": "user", "content": REMINDER.format(e)}]
        try:
            edits, explanation = parse((await llm.complete(messages)).get("content"), lines, ranges, masks)
        except FixError as e2:
            raise FixError(f"The model could not produce a usable fix ({e2}).") from None
    return {"finding_id": finding["id"], "path": finding["path"],
            "file_sha256": hashlib.sha256(full.read_bytes()).hexdigest(),
            "edits": edits, "explanation": explanation}
