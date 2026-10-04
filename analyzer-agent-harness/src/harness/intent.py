"""Decide what a chat message asks for: start a scan, stop one, or just talk.

One short LLM call with a JSON reply (small local models handle that far better than tool calls).
The result becomes the `action` of the chat reply, which the VS Code extension carries out:
only the extension can upload workspace files.
"""

import json
import logging
import re
from pathlib import PurePosixPath

from harness.files import PathError, check_rel_path
from harness.llm import _loads_lenient

log = logging.getLogger(__name__)

ACTIONS = ("scan", "scan_workspace", "scan_github", "cancel", "none")
MAX_FOLDERS_IN_PROMPT = 60

SYSTEM = """You route messages in the chat of a code security scanner. Decide whether the user wants
to START a scan, STOP the running scan, or is only asking or talking (no action).

Reply with ONE JSON object and nothing else:
{"action": "scan" | "scan_workspace" | "scan_github" | "cancel" | "none",
 "full": true or false,
 "paths": ["folder/or/file", ...],
 "url": "https://github.com/owner/repo" or null,
 "sure": true or false}

- "scan": scan or rescan the current project ("scan my code", "rescan", "check my changes",
  "scan again", "analyze the project"). For a GitHub session this rescans that repository.
- "scan_workspace": the user is in a GitHub session but wants their local workspace scanned.
- "scan_github": the user gives a https://github.com/owner/repo link to scan. Put it in "url".
- "cancel": stop / cancel / abort the running scan.
- "none": questions about findings, code, security advice, greetings, anything else.
- "full": true only if the user asks to scan everything again from scratch / a full scan.
- "paths": only if the user names part of the project ("only the backend", "src/api"). Use the
  project's real folder names from the list below. Otherwise [].
- "sure": true when the user clearly asks for the action. false when you only think a scan would
  help (e.g. "is my login code safe?" and there is no scan yet); then the user will be asked first.
"""


def _context(session, folders, has_scan, running):
    kind = (f"GitHub repository {session['repo_url']}" if session["target_type"] == "github"
            else "local workspace (uploaded from VS Code)")
    lines = [f"Session: {kind}.",
             f"A finished scan exists: {'yes' if has_scan else 'no'}.",
             f"A scan is running now: {'yes' if running else 'no'}."]
    if folders:
        lines.append("Project folders: " + ", ".join(folders[:MAX_FOLDERS_IN_PROMPT]))
    return "\n".join(lines)


def project_folders(files):
    """Top two levels of folders, for the model to map "the backend" to a real folder name."""
    out = set()
    for f in files:
        parts = PurePosixPath(f).parts[:-1]
        for depth in (1, 2):
            if len(parts) >= depth:
                out.add("/".join(parts[:depth]))
    return sorted(out, key=lambda p: (p.count("/"), p.lower()))


def _best_folder(name, folders):
    """The one folder a loose name most likely means ("api" -> "Kasephal-API"), or None.
    Tries exact name, then a whole word of the folder name, then any substring; within a tier a
    folder beats its own subfolders. Ambiguous names give None, so the user is asked instead."""
    low = name.lower()
    tiers = [
        lambda d: d.lower() == low or d.lower().endswith("/" + low),
        lambda d: low in re.split(r"[-_./ ]+", d.lower()),
        lambda d: low in d.lower(),
    ]
    for test in tiers:
        found = [d for d in folders if test(d)]
        top = [d for d in found if not any(d != o and d.startswith(o + "/") for o in found)]
        if len(top) == 1:
            return top[0]
        if top:
            return None
    return None


def resolve_paths(paths, files):
    """Map the model's paths onto real ones. Returns (resolved, unknown)."""
    folders = project_folders(files)
    resolved, unknown = [], []
    for raw in paths or []:
        p = str(raw).strip().removeprefix("./").strip("/")
        if not p or p == ".":
            continue
        try:
            check_rel_path(p)
        except PathError:
            unknown.append(str(raw))
            continue
        if any(f == p or f.startswith(p + "/") for f in files):
            resolved.append(p)
            continue
        match = _best_folder(p, folders)
        if match:
            resolved.append(match)
        else:
            unknown.append(p)
    return resolved, unknown


def parse(text):
    """The model's decision as a clean dict, or None if it is unreadable."""
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    data = _loads_lenient(m.group(0)) if m else None
    if not isinstance(data, dict):
        return None
    action = str(data.get("action", "none")).strip().lower()
    if action not in ACTIONS:
        return None
    paths = data.get("paths") or []
    if isinstance(paths, str):
        paths = [paths]
    return {"action": action, "full": data.get("full") is True,
            "paths": [str(p) for p in paths if isinstance(p, (str, int))][:20],
            "url": data.get("url") if isinstance(data.get("url"), str) else None,
            "sure": data.get("sure") is not False}


async def decide(llm, message, session, files, has_scan, running, history=()):
    """Ask the model what the message wants. Unreadable answers count as "none" (just chat)."""
    messages = [{"role": "system", "content": SYSTEM + "\n" + _context(session, project_folders(files), has_scan, running)}]
    for m in list(history)[-4:]:  # a little context, e.g. "yes" after "Shall I scan?"
        messages.append({"role": m["role"], "content": m["text"][:500]})
    messages.append({"role": "user", "content": message})
    reply = await llm.complete(messages)
    decision = parse(reply.get("content"))
    if decision is None:
        log.info("intent reply was not readable; treating the message as chat")
        return {"action": "none", "full": False, "paths": [], "url": None, "sure": True}
    decision["paths"] = [p for p in decision["paths"] if _mentioned(p, message)]
    log.info("intent: %s", json.dumps({k: v for k, v in decision.items() if k != "url"}))
    return decision


def _mentioned(path, message):
    """Small models add folders the user never named ("scan this project" -> ["Kasephal-API"]).
    Keep a folder only if the message names it, or one word of it (3+ letters)."""
    text = message.lower()
    words = [w for w in re.split(r"[-_./ ]+", str(path).lower()) if len(w) >= 3]
    return str(path).lower() in text or any(re.search(rf"\b{re.escape(w)}\b", text) for w in words)
