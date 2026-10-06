"""The fix agent: a coding agent that fixes findings.

For each file with findings, an agent reads and searches the code, edits files (any file, for an
import or a helper), reruns the scanners on its changes, and reports. All agents of one request
share an in-memory copy of the code; nothing on disk changes. The result is line edits per file,
which the VS Code extension shows as diffs and applies only after the user accepts.
"""

import asyncio
import difflib
import hashlib
import json
import logging
import tempfile
import threading
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from harness import files as files_mod
from harness import fix, web
from harness.llm import LLMError, LLMUnreachable
from harness.scanners import gitleaks, semgrep
from harness.scanners.findings import SEVERITIES, mask_lines

log = logging.getLogger(__name__)

MAX_STEPS = 24  # LLM calls per agent
MAX_CHECKS = 3
READ_MAX_LINES = 300
TOOL_RESULT_CHARS = 12000
TASK_CONTEXT_LINES = 15
WHOLE_FILE_LINES = 300  # files up to this size go into the task whole
TEXT_FLUSH_SECONDS = 0.25

SYSTEM = """You are a coding agent that fixes security findings in a project. Work like a careful engineer:
1. Look at the code around each finding, and at anything it depends on (read_file, search_code).
2. Fix the root cause with the smallest correct change, using edit_file. You may edit other files
   too, for example to add an import or a small helper. Keep the project's style and keep it working.
3. Call check_fixes to rerun the scanners on your changes, and fix what is still reported.
4. Call finish with a short summary, the ids you fixed, and why any were not fixed.
Rules:
- edit_file replaces an exact piece of text that you have read, and it must be unique in the file.
  Copy it exactly (without the line numbers) and include enough lines to make it unique.
- Text like "abcd****" is a hidden secret. Never copy it. Replace the whole line without it (for
  example read the value from an environment variable), or leave it alone.
- If a finding is a false alarm, do not change the code; say why in finish.
- Never invent files, functions or libraries. Do not reformat code you are not fixing."""

TOOLS = [
    {"type": "function", "function": {
        "name": "read_file", "description": "Read lines of a project file, with line numbers.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
            "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "search_code", "description": "Plain-text search across the project files.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "edit_file", "description": "Replace an exact, unique piece of text in a file.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "old_text": {"type": "string"}, "new_text": {"type": "string"}},
            "required": ["path", "old_text", "new_text"]}}},
    {"type": "function", "function": {
        "name": "check_fixes", "description": "Rerun the scanners on your changes. Lists your findings that are still reported.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "finish", "description": "End the task.",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string", "description": "What you changed and why, in plain language"},
            "fixed": {"type": "array", "items": {"type": "string"}, "description": "Ids of findings you fixed"},
            "not_fixed": {"type": "array", "items": {"type": "object", "properties": {
                "id": {"type": "string"}, "reason": {"type": "string"}}}}},
            "required": ["summary"]}}},
]


class AgentError(Exception):
    """A tool call failed; the message goes back to the model."""


def _numbered(lines, first):
    return "\n".join(f"{first + i:>5} | {l}" for i, l in enumerate(lines))


def _split(text):
    """Lines as the extension counts them: split on \\n, \\r\\n kept apart, no last empty line."""
    lines = [l.removesuffix("\r") for l in text.split("\n")]
    return lines[:-1] if lines and lines[-1] == "" else lines


class Edits:
    """The code as the agents see and change it: real lines, masked lines (what the model sees),
    and the original lines, for every file touched so far."""

    def __init__(self, code_dir, masks):
        self.code_dir = Path(code_dir)
        self.masks = masks  # path -> secret spans
        self.files = {}

    def file(self, path):
        if path not in self.files:
            try:
                full = files_mod.safe_join(self.code_dir, str(path))
            except files_mod.PathError as e:
                raise AgentError(str(e)) from None
            if not full.is_file():
                raise AgentError(f"{path}: file not found")
            data = full.read_bytes()
            if b"\x00" in data[:8192]:
                raise AgentError(f"{path} is a binary file")
            real = _split(data.decode(errors="replace"))
            self.files[path] = {"orig": list(real), "real": list(real),
                                "masked": mask_lines(real, 1, self.masks.get(path, [])),
                                "sha": hashlib.sha256(data).hexdigest()}
        return self.files[path]

    def changed(self):
        return {p: f for p, f in self.files.items() if f["real"] != f["orig"]}

    def read(self, path, start_line=1, end_line=None):
        f = self.file(path)
        n = len(f["masked"])
        start = max(int(start_line or 1), 1)
        end = min(int(end_line or start + READ_MAX_LINES - 1), n, start + READ_MAX_LINES - 1)
        if start > n:
            return f"{path} has only {n} lines."
        return f"{path} (lines {start}-{end} of {n}):\n" + _numbered(f["masked"][start - 1:end], start)

    def search(self, query, limit=20):
        limit = max(1, min(int(limit or 20), 50))
        hits = []
        for path, f in self.files.items():  # files being edited: search the current text
            hits += [(path, i, l.strip()[:300]) for i, l in enumerate(f["masked"], 1) if query in l]
        for path, line_no, text in files_mod.search(self.code_dir, str(query), limit * 2):
            if path not in self.files:
                masked = mask_lines([text], line_no, self.masks.get(path, []))[0] if path in self.masks else text
                hits.append((path, line_no, masked))
        return "\n".join(f"{p}:{n}: {t}" for p, n, t in hits[:limit]) or "No matches."

    def edit(self, path, old_text, new_text):
        f = self.file(path)
        if not old_text:
            raise AgentError("old_text is empty")
        old_text = old_text.replace("\r\n", "\n")
        new_text = new_text.replace("\r\n", "\n")
        text = "\n".join(f["masked"])
        n = text.count(old_text)
        if n == 0:
            raise AgentError("old_text was not found. Read the file again and copy the text exactly, "
                             "without line numbers.")
        if n > 1:
            raise AgentError(f"old_text appears {n} times. Include more surrounding lines.")
        i = text.index(old_text)
        a, b = text.count("\n", 0, i), text.count("\n", 0, i + len(old_text))
        start = sum(len(l) + 1 for l in f["masked"][:a])
        block = "\n".join(f["masked"][a:b + 1])
        new_block = block[:i - start] + new_text + block[i - start + len(old_text):]
        # Masked lines differ from the real ones. Writing them back is only safe when no mask is left.
        if f["masked"][a:b + 1] != f["real"][a:b + 1] and "****" in new_block:
            raise AgentError("this edit would copy a hidden secret (****). Replace the whole line without it.")
        new_lines = new_block.split("\n")
        f["real"][a:b + 1] = new_lines
        f["masked"][a:b + 1] = new_lines
        lo, hi = max(a - 3, 0), min(a + len(new_lines) + 3, len(f["masked"]))
        return f"Edited {path}. Now:\n" + _numbered(f["masked"][lo:hi], lo + 1)

    def apply_line_edits(self, path, edits):
        """Apply fix.propose's edits (made against the original file). Only for untouched files."""
        f = self.file(path)
        if f["real"] != f["orig"]:
            raise AgentError(f"{path} was already changed")
        for e in sorted(edits, key=lambda e: -e["start_line"]):
            new = e["replacement"].split("\n") if e["replacement"] else []
            f["real"][e["start_line"] - 1:e["end_line"]] = new
            f["masked"][e["start_line"] - 1:e["end_line"]] = new

    def proposals(self):
        """Whole-line edits per changed file, against the original file."""
        out = []
        for path, f in sorted(self.changed().items()):
            edits = line_edits(f["orig"], f["real"])
            if edits:
                out.append({"path": path, "file_sha256": f["sha"], "edits": edits})
        return out


def line_edits(orig, new):
    """Turn two versions of a file into sorted, non-overlapping whole-line replacements.
    Pure insertions take one unchanged neighbour line, because an edit replaces at least one line.
    So does a change to a single blank line: its replacement "" would mean "delete"."""
    groups = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, orig, new, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        if i1 == i2 or new[j1:j2] == [""]:  # insertion, or ambiguous ""
            if i1 > 0:
                i1, j1 = i1 - 1, j1 - 1
            elif orig:
                i2, j2 = i2 + 1, j2 + 1
            else:
                continue  # an empty file has no line to replace
        if groups and groups[-1][1] >= i1:
            g = groups[-1]
            groups[-1] = [g[0], max(g[1], i2), g[2], max(g[3], j2)]
        else:
            groups.append([i1, i2, j1, j2])
    return [{"start_line": i1 + 1, "end_line": i2, "replacement": "\n".join(new[j1:j2])} for i1, i2, j1, j2 in groups]


# --- checking with the scanners ---

_rules = {}
_rules_lock = threading.Lock()


def _load_rules(path):
    """Parse a rule file once per process. The result is stored by the worker thread itself, so a
    cancelled preload still fills the cache."""
    import yaml
    with _rules_lock:
        if path not in _rules:
            _rules[path] = yaml.safe_load(Path(path).read_text()).get("rules", [])
    return _rules[path]


async def preload_rules(configs):
    """Parse the rule files ahead of the first check (about 7 s for the merged file)."""
    try:
        await _rules_for(configs, ())
    except Exception:  # only an optimisation; the first check loads them otherwise
        log.warning("could not preload the Semgrep rules", exc_info=True)


async def _rules_for(configs, rule_ids):
    """Only the given Semgrep rules, from the local rule files. Loading 1000+ rules takes Semgrep
    about 50 s; a handful takes a few seconds."""
    wanted, out = set(rule_ids), []
    for c in configs:
        if not Path(c).is_file():
            continue
        rules = _rules.get(c)
        if rules is None:
            rules = await asyncio.to_thread(_load_rules, c)
        out += [r for r in rules if r.get("id") in wanted]
    return out


async def still_reported(edits, targets, all_findings, configs):
    """Which targets the scanners still report in the changed files, and which cannot be checked.
    Returns (still, unchecked) as sets of finding ids. SonarQube cannot rescan single files."""
    import yaml
    changed = edits.changed()
    checkable = [t for t in targets if t["path"] in changed and ({"semgrep", "gitleaks"} & set(t["tools"]))]
    unchecked = {t["id"] for t in targets if t["path"] in changed and t not in checkable}
    if not checkable:
        return set(), unchecked
    found = []
    with tempfile.TemporaryDirectory() as tmp:
        for path, f in changed.items():
            full = Path(tmp, "code", path)
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text("\n".join(f["real"]) + "\n")
        code = Path(tmp, "code")
        paths = sorted(changed)
        rules = await _rules_for(configs, {t["rule_id"] for t in checkable if "semgrep" in t["tools"]})
        if rules:
            Path(tmp, "rules.yml").write_text(yaml.safe_dump({"rules": rules}))
            found += await semgrep.scan(code, paths, [str(Path(tmp, "rules.yml"))], tmp)
        if any("gitleaks" in t["tools"] for t in checkable):
            found += await gitleaks.scan(code, paths, tmp)
    have_rules = {r["id"] for r in rules}
    ids_now = {f["id"] for f in found}
    # A finding keeps its id while its line text is the same. If the line changed but the problem did
    # not, the rule still fires in that file: count matches per rule and file before and after.
    # ponytail: counting per rule and file, not exact locations; good enough to tell fixed from not.
    key = lambda f: (f["rule_id"], f["path"])
    before, after = Counter(key(f) for f in all_findings), Counter(key(f) for f in found)
    still = set()
    for t in checkable:
        if "semgrep" in t["tools"] and t["rule_id"] not in have_rules and "gitleaks" not in t["tools"]:
            unchecked.add(t["id"])
        elif t["id"] in ids_now or after[key(t)] >= before[key(t)] > 0:
            still.add(t["id"])
    return still, unchecked


# --- the agent loop ---

def _task(edits, group, max_chars):
    """The findings, and the code: a small file whole (saves the agent a read_file call), else the
    lines around each finding."""
    parts = ["Fix these findings:"]
    whole = None
    try:
        f = edits.file(group[0]["path"])
        text = _numbered(f["masked"], 1)
        if len(f["masked"]) <= WHOLE_FILE_LINES and len(text) <= max_chars // 2:
            whole = text
    except AgentError:
        pass
    for t in group:
        parts.append(
            f"\n- id `{t['id']}`: {t['title']} ({t['severity']}, {t['cwe'] or 'no CWE'}, found by {', '.join(t['tools'])})\n"
            f"  File {t['path']}, lines {t['start_line']}-{t['end_line']}. Scanner: {t['message'][:300]}\n"
            f"  Reviewer's advice: {(t.get('fix_recommendation') or 'none')[:400]}")
        if whole is None:
            try:
                f = edits.file(t["path"])
                first = max(t["start_line"] - TASK_CONTEXT_LINES, 1)
                last = min(t["end_line"] + TASK_CONTEXT_LINES, len(f["masked"]))
                parts.append(f"  Code around it:\n{_numbered(f['masked'][first - 1:last], first)}")
            except AgentError as e:
                parts.append(f"  {e}")
    if whole is not None:
        parts.append(f"\nThe whole of {group[0]['path']} as it is now (no need to read it again):\n{whole}")
    return "\n".join(parts)


def _describe(name, args):
    """One activity line per tool call, like a coding agent's transcript."""
    if name == "read_file":
        lines = f":{args.get('start_line')}-{args.get('end_line') or ''}" if args.get("start_line") else ""
        return f"Read {args.get('path', '')}{lines}"
    if name == "fetch_url":
        return f"Fetch {urlsplit(str(args.get('url', ''))).hostname or args.get('url', '')}"
    return {"search_code": f"Search {str(args.get('query', ''))[:60]!r}", "edit_file": f"Edit {args.get('path', '')}",
            "web_search": f"Web search {str(args.get('query', ''))[:60]!r}",
            "check_fixes": "Check with the scanners", "finish": "Finish"}.get(name, name)


def _outcome(name, args, result):
    """A short line about a tool's result, shown under the tool line."""
    text = str(result)
    if text.startswith("Error:") or text.startswith("You already"):
        return text[:160]
    if name == "read_file":
        return text.split("\n", 1)[0].split("(", 1)[-1].rstrip("):") if "(lines" in text else text[:120]
    if name == "search_code":
        return "no matches" if text == "No matches." else f"{text.count(chr(10)) + 1} matches"
    if name == "edit_file":
        return f"+{len(str(args.get('new_text', '')).splitlines())} −{len(str(args.get('old_text', '')).splitlines())} lines"
    if name == "web_search":
        n = text.count('"url"')
        return f"{n} result{'s' if n != 1 else ''}"
    if name == "fetch_url":
        try:
            return json.loads(text).get("title") or "read"
        except ValueError:
            return "read"
    if name == "check_fixes":
        states = Counter("still reported" if "STILL" in l else "not changed" if "not changed" in l
                         else "not checkable" if "cannot be checked" in l else "no longer reported"
                         for l in text.splitlines())
        return ", ".join(f"{n} {s}" for s, n in states.items())
    return ""


async def run_agent(llm, edits, group, all_findings, configs, say, web_url=None):
    """Fix one group of findings. Returns {"summary", "fixed", "not_fixed"}; raises LLMError when
    the server cannot handle tool calls at all (the caller then falls back to one-shot fixes)."""
    tools_all = TOOLS + web.TOOLS if web_url else TOOLS
    messages = [{"role": "system", "content": SYSTEM + ("\n" + web.PROMPT if web_url else "")},
                {"role": "user", "content": _task(edits, group, llm.max_code_chars)}]
    checks = 0
    for step in range(MAX_STEPS):
        tools = tools_all if step < MAX_STEPS - 1 else [t for t in TOOLS if t["function"]["name"] == "finish"]
        reply = await llm.complete(messages, tools, on_text=lambda d, thinking: say("thinking" if thinking else "text", d))
        calls = reply.get("tool_calls") or []
        if not calls:
            if step == 0 and not edits.changed():
                raise LLMError("the model did not use the tools")
            return {"summary": (reply.get("content") or "").strip(), "fixed": [], "not_fixed": []}
        messages.append({"role": "assistant", "content": reply.get("content") or "", "tool_calls": [
            {"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c["arguments"]}}
            for c in calls]})
        done = None
        for c in calls:
            try:
                args = json.loads(c["arguments"] or "{}")
                if not isinstance(args, dict):
                    raise ValueError
            except ValueError:
                args, result = {}, "Error: the arguments were not a JSON object."
            else:
                await say("tool", _describe(c["name"], args))
                try:
                    if c["name"] == "read_file":
                        result = edits.read(args["path"], args.get("start_line"), args.get("end_line"))
                    elif c["name"] == "search_code":
                        result = edits.search(args["query"], args.get("limit"))
                    elif c["name"] == "edit_file":
                        result = edits.edit(args["path"], args["old_text"], args["new_text"])
                    elif c["name"] == "check_fixes":
                        checks += 1
                        if checks > MAX_CHECKS:
                            result = "You already checked enough times. Call finish."
                        else:
                            still, unchecked = await still_reported(edits, group, all_findings, configs)
                            result = _check_text(group, edits, still, unchecked)
                    elif web_url and c["name"] in web.NAMES:
                        result = json.dumps(await web.call(web_url, c["name"], args))
                    elif c["name"] == "finish":
                        done = args
                        result = "Done."
                    else:
                        result = f"Error: unknown tool {c['name']}"
                except AgentError as e:
                    result = f"Error: {e}"
                except (KeyError, TypeError, ValueError) as e:
                    result = f"Error: bad arguments ({e})"
            if c["name"] != "finish" and _outcome(c["name"], args, result):
                await say("result", _outcome(c["name"], args, result))
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": str(result)[:TOOL_RESULT_CHARS]})
        if done is not None:
            return {"summary": str(done.get("summary") or "").strip(),
                    "fixed": [str(i) for i in done.get("fixed") or [] if isinstance(i, str)],
                    "not_fixed": [n for n in done.get("not_fixed") or [] if isinstance(n, dict)]}
    return {"summary": "The agent stopped after the maximum number of steps.", "fixed": [], "not_fixed": []}


def _check_text(group, edits, still, unchecked):
    changed = edits.changed()
    lines = []
    for t in group:
        if t["path"] not in changed:
            state = "its file is not changed"
        elif t["id"] in still:
            state = "STILL REPORTED"
        elif t["id"] in unchecked:
            state = "cannot be checked automatically (SonarQube); make sure your change fixes it"
        else:
            state = "no longer reported"
        lines.append(f"- `{t['id']}` {t['title']} in {t['path']}: {state}")
    return "\n".join(lines)


async def _one_shot(llm, edits, group):
    """Fallback without tool calls: one proposal per finding (fix.propose)."""
    notes = {}
    for t in group:
        try:
            p = await fix.propose(llm, t, edits.code_dir)
            edits.apply_line_edits(t["path"], p["edits"])
            notes[t["id"]] = p["explanation"]
        except (fix.FixError, AgentError) as e:
            notes[t["id"]] = f"Not fixed: {e}"
    return {"summary": " ".join(f"`{i[:8]}`: {n}" for i, n in notes.items()), "fixed": [], "not_fixed": []}


async def fix_findings(llm, cfg, code_dir, targets, all_findings, report):
    """Run one agent per file with findings (at most LLM_MAX_PARALLEL at once), then check the
    result with the scanners. `report(percent, message)` is awaited for progress; each message is
    a JSON event {"file", "kind", "text"} (see the contract), so the client can show a live transcript."""
    masks = {}
    for f in all_findings:
        masks.setdefault(f["path"], []).extend(tuple(s) for s in f.get("_mask", []))
    edits = Edits(code_dir, masks)
    groups = {}
    for t in sorted(targets, key=lambda t: (SEVERITIES.index(t["severity"]), t["path"], t["start_line"])):
        groups.setdefault(t["path"], []).append(t)
    sem = asyncio.Semaphore(max(1, cfg.llm_max_parallel))
    done = 0
    results = {}
    use_tools = cfg.llm_tool_calling
    pending = {}  # file -> [kind of streamed text, text not sent yet, time of the last send]
    loop = asyncio.get_running_loop()

    async def emit(file, kind, text):
        await report(int(done * 90 / max(len(groups), 1)), json.dumps({"file": file, "kind": kind, "text": text}))

    async def flush(file):
        buf = pending.get(file)
        if buf and buf[1]:
            text, buf[1], buf[2] = buf[1], "", loop.time()
            await emit(file, buf[0], text)

    async def one(path, group):
        nonlocal done, use_tools
        async with sem:
            async def say(kind, text):
                if kind in ("text", "thinking"):  # batch streamed text, about four sends a second per file
                    buf = pending.setdefault(path, [kind, "", 0.0])
                    if buf[0] != kind:
                        await flush(path)
                        buf[0] = kind
                    buf[1] += text
                    if loop.time() - buf[2] >= TEXT_FLUSH_SECONDS:
                        await flush(path)
                    return
                await flush(path)
                await emit(path, kind, text)
            await emit(path, "start", f"{len(group)} finding{'s' if len(group) > 1 else ''}")
            r = None
            if use_tools:
                try:
                    r = await run_agent(llm, edits, group, all_findings, cfg.semgrep_configs, say, cfg.web_search_url)
                except LLMUnreachable:
                    raise
                except LLMError as e:
                    log.warning("fix agent could not use tools (%s); using one-shot fixes", e)
                    use_tools = False
            if r is None:
                await say("status", "Making one-shot fixes (the model cannot use tools)")
                r = await _one_shot(llm, edits, group)
            await flush(path)
            results[path] = r
            done += 1
            await emit(path, "done", f"Finished {done} of {len(groups)} files")

    await asyncio.gather(*(one(p, g) for p, g in groups.items()))
    await report(92, json.dumps({"file": None, "kind": "status", "text": "Checking all changes with the scanners"}))
    still, unchecked = await still_reported(edits, targets, all_findings, cfg.semgrep_configs)
    changed = edits.changed()
    reasons = {str(n.get("id")): str(n.get("reason") or "") for r in results.values() for n in r["not_fixed"]}
    outcomes = []
    for t in targets:
        if t["path"] not in changed:
            status, note = "not_fixed", reasons.get(t["id"]) or "The agent did not change this file."
        elif t["id"] in still:
            status, note = "still_reported", "The scanners still report it after the change."
        elif t["id"] in unchecked:
            status, note = "not_verified", "Changed, but SonarQube cannot recheck one file. Rescan to confirm."
        else:
            status, note = "fixed", "The scanners no longer report it."
        outcomes.append({"finding_id": t["id"], "status": status, "note": note})
    summary = "\n".join(f"- `{p}`: {r['summary']}" for p, r in results.items() if r["summary"])
    return {"files": edits.proposals(), "summary": summary, "results": outcomes}
