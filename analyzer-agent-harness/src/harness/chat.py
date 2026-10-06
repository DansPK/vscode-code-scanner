"""The chat agent: answers questions about the code and the findings."""

import json
import logging
import re
from collections import Counter
from pathlib import Path

from harness import files
from harness.llm import LLMError, LLMUnreachable
from harness.scanners.findings import SEVERITIES, mask_lines, read_lines

log = logging.getLogger(__name__)

MAX_TOOL_STEPS = 8
HISTORY_MESSAGES = 20
SUMMARY_FINDINGS = 40
READ_FILE_MAX_LINES = 400
SEARCH_LIMIT_MAX = 50

SYSTEM = """You are a security assistant inside a code scanner. You help the user understand
the scan findings for their project and how to fix them. Answer in plain language, using Markdown.
When you talk about a finding, include its id in backticks so the user can find it.
Scans start when the user asks for one in this chat (for example "scan this project").
Never invent findings: if there are none, say so."""

TOOLS = [
    {"type": "function", "function": {
        "name": "list_findings", "description": "List findings from the latest scan, with optional filters.",
        "parameters": {"type": "object", "properties": {
            "severity": {"type": "array", "items": {"type": "string", "enum": SEVERITIES}},
            "tool": {"type": "array", "items": {"type": "string"}},
            "path": {"type": "string", "description": "Only findings in this file or folder"},
            "limit": {"type": "integer", "default": 20}}}}},
    {"type": "function", "function": {
        "name": "get_finding", "description": "Get all details of one finding by id.",
        "parameters": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}}},
    {"type": "function", "function": {
        "name": "read_file", "description": "Read lines of a project file. Paths are relative to the project root.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start_line": {"type": "integer", "default": 1},
            "end_line": {"type": "integer"}}, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "Plain-text search across the project files.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "limit": {"type": "integer", "default": 20}}, "required": ["query"]}}},
]


class Workspace:
    """What the agent may look at: one session's code folder and latest findings."""

    def __init__(self, code_dir, findings):
        self.code_dir = Path(code_dir)
        self.findings = findings
        self.by_id = {f["id"]: f for f in findings}
        self.masks = {}
        for f in findings:
            self.masks.setdefault(f["path"], set()).update(tuple(s) for s in f.get("_mask", []))

    def _brief(self, f):
        return {k: f[k] for k in ("id", "severity", "title", "path", "start_line", "verdict", "tools")}

    def list_findings(self, severity=None, tool=None, path=None, limit=20):
        out = [f for f in self.findings
               if (not severity or f["severity"] in severity)
               and (not tool or set(tool) & set(f["tools"]))
               and (not path or f["path"] == path or f["path"].startswith(path.rstrip("/") + "/"))]
        return {"total": len(out), "findings": [self._brief(f) for f in out[:max(1, min(int(limit), 100))]]}

    def get_finding(self, id):
        f = self.by_id.get(id)
        if not f:
            return {"error": "finding not found"}
        return {k: v for k, v in f.items() if not k.startswith("_")}

    def read_file(self, path, start_line=1, end_line=None):
        try:
            full = files.safe_join(self.code_dir, path)
        except files.PathError as e:
            return {"error": str(e)}
        if not full.is_file():
            return {"error": "file not found"}
        lines = read_lines(full)
        start = max(int(start_line or 1), 1)
        end = min(int(end_line or start + READ_FILE_MAX_LINES - 1), len(lines), start + READ_FILE_MAX_LINES - 1)
        chunk = mask_lines(lines[start - 1:end], start, self.masks.get(path, []))
        return {"path": path, "start_line": start, "end_line": end, "total_lines": len(lines),
                "text": "\n".join(f"{start + i:>5} | {l}" for i, l in enumerate(chunk))}

    def search_code(self, query, limit=20):
        limit = max(1, min(int(limit), SEARCH_LIMIT_MAX))
        hits = []
        for path, line_no, text in files.search(self.code_dir, str(query), limit):
            masked = mask_lines([text], line_no, self.masks.get(path, []))[0] if path in self.masks else text
            hits.append({"path": path, "line": line_no, "text": masked})
        return {"results": hits}

    def call(self, name, args):
        fn = {"list_findings": self.list_findings, "get_finding": self.get_finding,
              "read_file": self.read_file, "search_code": self.search_code}.get(name)
        if fn is None:
            return {"error": f"unknown tool {name}"}
        try:
            return fn(**args)
        except (TypeError, ValueError) as e:
            return {"error": f"bad arguments: {e}"}

    def summary(self):
        if not self.findings:
            return "There are no findings yet (no scan, or the scan found nothing)."
        sev = Counter(f["severity"] for f in self.findings)
        counts = ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s])
        top = sorted(self.findings, key=lambda f: (SEVERITIES.index(f["severity"]), f["path"]))
        lines = [f"- `{f['id']}` {f['severity']} {f['path']}:{f['start_line']} {f['title']} ({f['verdict']})"
                 for f in top[:SUMMARY_FINDINGS]]
        more = len(top) - SUMMARY_FINDINGS
        return (f"Latest scan: {len(self.findings)} findings ({counts}).\n" + "\n".join(lines)
                + (f"\n...and {more} more." if more > 0 else ""))

    def named_files(self, message, max_files=2):
        """Files the user's message names, by path or by file name."""
        words = set(re.findall(r"[\w./-]+", message))
        found = []
        for rel in files.walk_files(self.code_dir):
            if rel in words or (len(Path(rel).name) > 3 and Path(rel).name in words):
                found.append(rel)
                if len(found) >= max_files:
                    break
        return found


def _mentioned_ids(text, workspace):
    return [i for i in re.findall(r"[0-9a-f]{32}", text or "") if i in workspace.by_id]


def _named_files_text(llm, workspace, message):
    budget = llm.max_code_chars // 2
    return "".join(f"\n\nFile {rel}:\n{workspace.read_file(rel).get('text', '')[:budget]}"
                   for rel in workspace.named_files(message))


def _without_tool_turns(messages):
    """Drop tool calls and tool results, keeping what tools found as plain text for the model."""
    out = []
    for m in messages:
        if m["role"] == "tool":
            out.append({"role": "user", "content": f"(Tool result) {m['content'][:4000]}"})
        elif m["role"] == "assistant" and m.get("tool_calls"):
            if m.get("content"):
                out.append({"role": "assistant", "content": m["content"]})
        else:
            out.append(m)
    return out


async def chat(llm, workspace, message, history, tool_calling):
    """Return (reply_markdown, finding_ids)."""
    system = SYSTEM + "\n\n" + workspace.summary()
    if not tool_calling:
        system += _named_files_text(llm, workspace, message)
    messages = [{"role": "system", "content": system}]
    messages += [{"role": m["role"], "content": m["text"]} for m in history[-HISTORY_MESSAGES:]]
    messages.append({"role": "user", "content": message})

    looked_at = []
    tools = TOOLS if tool_calling else None
    for _ in range(MAX_TOOL_STEPS):
        try:
            reply = await llm.complete(messages, tools)
        except LLMUnreachable:
            raise
        except LLMError:
            if tools is None:
                raise
            # Some local servers fail to parse a small model's tool-call output. Answer without tools instead.
            log.warning("LLM call with tools failed; retrying this turn without tools")
            tools = None
            messages = _without_tool_turns(messages)
            messages[0] = {"role": "system", "content": messages[0]["content"] + _named_files_text(llm, workspace, message)}
            reply = await llm.complete(messages, None)
        if not reply.get("tool_calls"):
            break
        messages.append({"role": "assistant", "content": reply.get("content") or "", "tool_calls": [
            {"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c["arguments"]}}
            for c in reply["tool_calls"]]})
        for c in reply["tool_calls"]:
            try:
                args = json.loads(c["arguments"] or "{}")
            except json.JSONDecodeError:
                args = None
            result = workspace.call(c["name"], args) if isinstance(args, dict) else {"error": "arguments are not JSON"}
            if c["name"] == "get_finding" and "id" in result:
                looked_at.append(result["id"])
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": json.dumps(result)[:20000]})
    else:
        messages.append({"role": "user", "content": "Stop using tools now and answer with what you have."})
        reply = await llm.complete(messages, None)

    text = (reply.get("content") or "").strip() or "Sorry, I could not come up with an answer."
    ids = list(dict.fromkeys(_mentioned_ids(text, workspace) + looked_at))
    return text, ids


SUMMARY_FINDINGS_FOR_LLM = 60
SUMMARY_BULLETS = 3
SUMMARY_SYSTEM = """You summarise a code security scan in a few words. You get the findings, most serious first.
Reply in exactly this form and nothing else:
Overall: <one sentence: how risky the project looks and why>
- <the most important thing to fix first: the problem, the file, and one finding id in backticks>
- <the second>
- <the third>
At most three bullets, each under 20 words, each with at most one finding id. Group findings that share one fix.
Use only the findings given: never invent findings, numbers or scores."""


def _concise(text):
    """Keep the one-sentence overall and at most three bullets, whatever else the model wrote."""
    overall, bullets = None, []
    for line in (text or "").splitlines():
        line = line.strip()
        m = re.match(r"[*_#\s]*overall[*_]*\s*:?[*_]*\s*(.+)", line, re.I)
        if m and overall is None:
            overall = _first_sentence(m.group(1).strip("*_ "))
            continue
        m = re.match(r"(?:[-*•]|\d+[.)])\s+(.+)", line)
        if m and len(bullets) < SUMMARY_BULLETS:
            bullets.append(m.group(1).strip())
    if overall is None and not bullets:
        return _first_sentence(text)
    parts = [overall] if overall else []
    if bullets:
        parts.append("**Fix first:**\n" + "\n".join(f"{i}. {b}" for i, b in enumerate(bullets, 1)))
    return "\n\n".join(parts)


def _first_sentence(text):
    m = re.match(r"(.+?[.!?])(\s|$)", (text or "").strip(), re.DOTALL)
    return (m.group(1) if m else (text or "")).replace("\n", " ").strip()[:200]


def summary_stats(findings):
    """The facts part of the summary, two lines. Needs no LLM."""
    if not findings:
        return "**No findings.**"
    sev = Counter(f["severity"] for f in findings)
    real = sum(f["verdict"] == "likely_real" for f in findings)
    fp = sum(f["verdict"] == "likely_false_positive" for f in findings)
    counts = " · ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s])
    n = len(findings)
    line = f"**{n} finding{'s' if n != 1 else ''}** ({counts}). "
    looks = lambda k: "looks" if k == 1 else "look"
    if fp == n:
        line += "It looks like a false alarm." if n == 1 else "All look like false alarms."
    else:
        line += f"{real} {looks(real)} real" + (f", {fp} {looks(fp)} like false alarms." if fp else ".")
    worth = [f for f in findings if f["verdict"] != "likely_false_positive"]
    if worth:
        top = Counter(f["path"] for f in worth).most_common(3)
        line += "\nMost affected: " + ", ".join(f"`{p}` ({n})" for p, n in top) + "."
    return line


async def summarize(llm, workspace):
    """Return (markdown, finding_ids): two lines of counts, then one sentence and up to three
    things to fix first from the LLM. Without findings worth fixing, the counts are enough."""
    stats = summary_stats(workspace.findings)
    findings = [f for f in workspace.findings if f["verdict"] != "likely_false_positive"]
    if not findings:
        return stats, []
    top = sorted(findings, key=lambda f: (SEVERITIES.index(f["severity"]), f["verdict"] != "likely_real", f["path"]))
    listing = "\n".join(f"- `{f['id']}` {f['severity']} {f['title']} in {f['path']}:{f['start_line']}"
                        f" ({f['verdict']}). {_first_sentence(f.get('explanation') or f['message'])}"
                        for f in top[:SUMMARY_FINDINGS_FOR_LLM])
    more = len(top) - SUMMARY_FINDINGS_FOR_LLM
    prompt = listing + (f"\n...and {more} less serious ones." if more > 0 else "")
    try:
        reply = await llm.complete([{"role": "system", "content": SUMMARY_SYSTEM}, {"role": "user", "content": prompt}])
        text = _concise(reply.get("content") or "")
    except LLMError as e:
        log.warning("summary assessment failed: %s", e)
        text = ""
    if not text:
        return stats, []
    return stats + "\n\n" + text, _mentioned_ids(text, workspace)
