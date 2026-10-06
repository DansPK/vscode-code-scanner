"""Tool logic from the contract, independent of MCP. Every method takes the caller's user id."""

import asyncio
import errno
import json
import logging
import re
import secrets
import shutil
import tempfile
from pathlib import Path

from harness import chat as chat_mod
from harness import uploads
from harness.db import now
from harness.files import PathError, check_rel_path
from harness.scanners import sonarqube
from harness.scanners.findings import SEVERITIES, TOOLS

log = logging.getLogger(__name__)

SHA_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_NAME = 200
MAX_CHAT_CHARS = 8000
MAX_MANIFEST_ENTRIES = 200_000
MAX_FINDINGS_PAGE = 1000
MAX_FIX_BATCH = 200
ASK_BEFORE_FIXING_OVER = 10  # bigger batches take minutes of LLM time, so the user confirms first
SECONDS_PER_FILE = 40  # rough time for the agent to fix one file, several files run at once


class UserError(Exception):
    """An error whose message is shown to the user as-is."""


class Service:
    def __init__(self, cfg, db, scans, llm, sonar_client=None, github=None):
        self.cfg = cfg
        self.db = db
        self.scans = scans
        self.llm = llm
        self.sonar = sonar_client or sonarqube.SonarClient(cfg.sonar_host_url, cfg.sonar_token)
        self.github = github  # set in Milestone 5
        self._session_locks = {}

    # --- helpers ---

    def _session(self, user, session_id):
        row = self.db.one("SELECT * FROM sessions WHERE id=? AND owner=?", (str(session_id), user))
        if row is None:
            raise UserError("session not found")
        return row

    def _scan(self, user, scan_id):
        row = self.db.one("SELECT s.* FROM scans s JOIN sessions x ON x.id = s.session_id "
                          "WHERE s.id=? AND x.owner=?", (str(scan_id), user))
        if row is None:
            raise UserError("scan not found")
        return row

    def session_dir(self, session_id):
        return self.cfg.sessions_dir / session_id

    def code_dir(self, session_id):
        return self.session_dir(session_id) / "code"

    def _lock(self, session_id):
        return self._session_locks.setdefault(session_id, asyncio.Lock())

    def _manifest(self, session_id):
        return {r["path"]: r for r in self.db.all(
            "SELECT path, sha256, size FROM manifest_files WHERE session_id=?", (session_id,))}

    def _set_manifest(self, session_id, entries):
        with self.db.conn() as c:
            c.execute("DELETE FROM manifest_files WHERE session_id=?", (session_id,))
            c.executemany("INSERT INTO manifest_files VALUES (?,?,?,?)",
                          [(session_id, e["path"], e["sha256"], e["size"]) for e in entries])

    # --- sessions ---

    def create_session(self, user, name=None, target_type="workspace", repo_url=None):
        if target_type not in ("workspace", "github"):
            raise UserError("target_type must be 'workspace' or 'github'")
        if target_type == "github":
            if not repo_url:
                raise UserError("repo_url is required for a github session")
            from harness import github
            owner, repo = github.parse_url(repo_url)
            repo_url = f"https://github.com/{owner}/{repo}"
            name = name or f"{owner}/{repo}"
        else:
            repo_url = None
        name = (name or f"Workspace scan {now()[:16].replace('T', ' ')}").strip()[:MAX_NAME]
        sid = secrets.token_hex(12)
        ts = now()
        self.db.run("INSERT INTO sessions (id, owner, name, target_type, repo_url, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?)", (sid, user, name, target_type, repo_url, ts, ts))
        self.code_dir(sid).mkdir(parents=True, exist_ok=True)
        log.info("session created: %s", sid)
        return {"session_id": sid}

    def _session_fields(self, row):
        last = self.db.one("SELECT created_at, status FROM scans WHERE session_id=? "
                           "ORDER BY created_at DESC, rowid DESC LIMIT 1", (row["id"],))
        return {"session_id": row["id"], "name": row["name"], "target_type": row["target_type"],
                "repo_url": row["repo_url"], "created_at": row["created_at"],
                "last_scan_at": last["created_at"] if last else None,
                "last_scan_status": last["status"] if last else None}

    def list_sessions(self, user):
        rows = self.db.all("SELECT * FROM sessions WHERE owner=? ORDER BY updated_at DESC", (user,))
        return {"sessions": [self._session_fields(r) for r in rows]}

    def get_session(self, user, session_id, message_limit=50):
        row = self._session(user, session_id)
        limit = max(0, min(int(message_limit), 500))
        msgs = self.db.all("SELECT role, text, finding_ids, created_at FROM messages WHERE session_id=? "
                           "ORDER BY id DESC LIMIT ?", (row["id"], limit))
        latest = self.db.one("SELECT id FROM scans WHERE session_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                             (row["id"],))
        count = self.db.one("SELECT COUNT(*) AS n FROM manifest_files WHERE session_id=?", (row["id"],))["n"]
        return {"session": self._session_fields(row),
                "messages": [{**m, "finding_ids": json.loads(m["finding_ids"])} for m in reversed(msgs)],
                "latest_scan_id": latest["id"] if latest else None, "file_count": count}

    def rename_session(self, user, session_id, name):
        row = self._session(user, session_id)
        name = (name or "").strip()
        if not name:
            raise UserError("name must not be empty")
        self.db.run("UPDATE sessions SET name=?, updated_at=? WHERE id=?", (name[:MAX_NAME], now(), row["id"]))
        return {"ok": True}

    async def delete_session(self, user, session_id):
        row = self._session(user, session_id)
        sid = row["id"]
        await self.scans.cancel_session(sid)
        with self.db.conn() as c:
            for table in ("messages", "manifest_files", "pending_manifests", "uploads", "findings", "scans"):
                c.execute(f"DELETE FROM {table} WHERE session_id=?", (sid,))
            c.execute("DELETE FROM sessions WHERE id=?", (sid,))
        await asyncio.to_thread(shutil.rmtree, self.session_dir(sid), True)
        await self.sonar.delete_project(sonarqube.project_key(sid))
        log.info("session deleted: %s", sid)
        return {"ok": True}

    # --- sync and upload ---

    def sync_files(self, user, session_id, manifest):
        row = self._session(user, session_id)
        if row["target_type"] != "workspace":
            raise UserError("sync_files is only for workspace sessions")
        if not isinstance(manifest, list) or len(manifest) > MAX_MANIFEST_ENTRIES:
            raise UserError("manifest must be a list of at most %d entries" % MAX_MANIFEST_ENTRIES)
        entries, seen = [], set()
        for e in manifest:
            try:
                path = check_rel_path(e.get("path"))
            except (PathError, AttributeError) as err:
                raise UserError(str(err)) from err
            sha, size = e.get("sha256"), e.get("size")
            if not isinstance(sha, str) or not SHA_RE.match(sha):
                raise UserError(f"bad sha256 for {path}")
            if not isinstance(size, int) or size < 0:
                raise UserError(f"bad size for {path}")
            if path in seen:
                raise UserError(f"duplicate path {path}")
            seen.add(path)
            entries.append({"path": path, "sha256": sha, "size": size})
        current = self._manifest(row["id"])
        need = [e["path"] for e in entries if current.get(e["path"], {}).get("sha256") != e["sha256"]]
        delete = sorted(set(current) - seen)
        self.db.run("INSERT OR REPLACE INTO pending_manifests VALUES (?,?,?)",
                    (row["id"], json.dumps(entries), now()))
        return {"need": need, "delete": delete, "unchanged_count": len(entries) - len(need)}

    def request_upload(self, user, session_id, size_bytes, sha256):
        row = self._session(user, session_id)
        if row["target_type"] != "workspace":
            raise UserError("request_upload is only for workspace sessions")
        if not isinstance(size_bytes, int) or size_bytes <= 0:
            raise UserError("size_bytes must be a positive integer")
        if size_bytes > self.cfg.upload_max_mb * 1024 * 1024:
            raise UserError(f"archive is larger than the server limit of {self.cfg.upload_max_mb} MB")
        if not isinstance(sha256, str) or not SHA_RE.match(sha256):
            raise UserError("sha256 must be 64 lowercase hex characters")
        upload_id, url, expires = uploads.create(self.cfg, self.db, row["id"], size_bytes, sha256)
        from datetime import datetime, timezone
        return {"upload_id": upload_id, "upload_url": url,
                "expires_at": datetime.fromtimestamp(expires, timezone.utc).isoformat(timespec="seconds")}

    def _apply_upload(self, sid, upload_id, deleted_paths):
        """Make the pending manifest current: unpack the upload, delete removed files.
        Returns (all paths, changed paths). Runs in a worker thread."""
        current = self._manifest(sid)
        pending_row = self.db.one("SELECT manifest FROM pending_manifests WHERE session_id=?", (sid,))
        if pending_row is None:
            if upload_id:
                raise UserError("call sync_files before uploading")
            return sorted(current), set()
        pending = {e["path"]: e for e in json.loads(pending_row["manifest"])}
        need = {p for p, e in pending.items() if current.get(p, {}).get("sha256") != e["sha256"]}
        if len(deleted_paths or []) > MAX_MANIFEST_ENTRIES:
            raise UserError("too many deleted paths")
        for p in deleted_paths or []:
            check_rel_path(p)
        to_delete = (set(current) | set(deleted_paths or [])) - set(pending)
        code = self.code_dir(sid)
        code.mkdir(parents=True, exist_ok=True)

        written = []
        staging = None
        if need:
            if not upload_id:
                raise UserError(f"{len(need)} files changed; upload them first")
            archive = uploads.take(self.db, upload_id, sid)
            staging = Path(tempfile.mkdtemp(dir=self.session_dir(sid), prefix="staging-"))
            try:
                written = uploads.unpack(archive, staging,
                                         {p: pending[p]["sha256"] for p in need},
                                         self.cfg.upload_max_unpacked_mb * 1024 * 1024)
                missing = need - set(written)
                if missing:
                    raise UserError(f"the upload is missing {len(missing)} changed files, "
                                    f"for example {sorted(missing)[0]}")
            except (uploads.UnpackError, UserError):
                shutil.rmtree(staging, ignore_errors=True)
                raise
        try:
            for p in sorted(to_delete, reverse=True):
                target = code / p
                if target.is_symlink() or target.is_file():
                    target.unlink()
                elif target.is_dir():
                    shutil.rmtree(target)
            if staging:
                uploads.move_into(staging, code, written)
        finally:
            if staging:
                shutil.rmtree(staging, ignore_errors=True)
        self._set_manifest(sid, list(pending.values()))
        self.db.run("DELETE FROM pending_manifests WHERE session_id=?", (sid,))
        if upload_id:
            uploads.discard(self.db, upload_id)
        return sorted(pending), need

    # --- scans ---

    def _scope(self, paths, files):
        """Clean up the folders/files a scan is limited to, and check each one exists."""
        scope = []
        for p in paths or []:
            p = str(p).strip().removeprefix("./").strip("/")
            if not p or p == ".":
                return []  # the whole project
            try:
                check_rel_path(p)
            except PathError as e:
                raise UserError(str(e)) from e
            if not any(f == p or f.startswith(p + "/") for f in files):
                raise UserError(f"there are no files under {p!r} in this project")
            scope.append(p)
        return scope

    async def start_scan(self, user, session_id, upload_id=None, deleted_paths=None, full=False, paths=None):
        row = self._session(user, session_id)
        sid = row["id"]
        if len(paths or []) > 100:
            raise UserError("too many paths")
        async with self._lock(sid):
            if self.scans.is_running(sid):
                raise UserError("a scan is already running for this session")
            web_base = None
            if row["target_type"] == "workspace" and paths:
                # Check the folders against the files being uploaded before anything is applied.
                pending = self.db.one("SELECT manifest FROM pending_manifests WHERE session_id=?", (sid,))
                upcoming = [e["path"] for e in json.loads(pending["manifest"])] if pending else list(self._manifest(sid))
                self._scope(paths, upcoming)
            if row["target_type"] == "workspace":
                try:
                    files, changed = await asyncio.to_thread(self._apply_upload, sid, upload_id, deleted_paths)
                except (uploads.UnpackError, PathError) as e:
                    raise UserError(str(e)) from e
                except OSError as e:
                    if e.errno == errno.ENOSPC:
                        raise UserError("The server disk is full.") from e
                    raise
            else:
                if self.github is None:
                    raise UserError("GitHub scans are not available")
                files, changed, web_base = await self.github.prepare(row, self.code_dir(sid))
            if not files:
                raise UserError("there are no files to scan")
            scope = self._scope(paths, files)
            scan_id = self.scans.start(row, {"files": files, "changed": changed, "full": bool(full),
                                             "web_base": web_base, "paths": scope})
        return {"scan_id": scan_id}

    def get_scan_status(self, user, scan_id):
        return self.scans.status(self._scan(user, scan_id)["id"])

    async def watch_scan(self, user, scan_id, report):
        return await self.scans.watch(self._scan(user, scan_id)["id"], report)

    async def cancel_scan(self, user, scan_id):
        row = self._scan(user, scan_id)
        if row["status"] not in ("queued", "running"):
            raise UserError(f"the scan is already {row['status']}")
        await self.scans.cancel(row["id"])
        return {"ok": True}

    def _latest_scan_id(self, sid):
        row = self.scans.latest_done(sid)
        return row["id"] if row else None

    def get_findings(self, user, session_id, scan_id=None, severity=None, tool=None, path=None,
                     limit=200, offset=0):
        row = self._session(user, session_id)
        if scan_id:
            scan = self._scan(user, scan_id)
            if scan["session_id"] != row["id"]:
                raise UserError("scan not found")
        else:
            scan_id = self._latest_scan_id(row["id"])
            if scan_id is None:
                return {"findings": [], "total": 0}
        for s in severity or []:
            if s not in SEVERITIES:
                raise UserError(f"unknown severity {s}")
        for t in tool or []:
            if t not in TOOLS:
                raise UserError(f"unknown tool {t}")
        found = [f for f in self.db.load_findings(scan_id)
                 if (not severity or f["severity"] in severity)
                 and (not tool or set(tool) & set(f["tools"]))
                 and (not path or f["path"] == path or f["path"].startswith(path.rstrip("/") + "/"))]
        found.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["path"], f["start_line"]))
        limit = max(1, min(int(limit), MAX_FINDINGS_PAGE))
        offset = max(0, int(offset))
        return {"findings": found[offset:offset + limit], "total": len(found)}

    # --- chat ---

    async def chat(self, user, session_id, message):
        row = self._session(user, session_id)
        message = (message or "").strip()
        if not message:
            raise UserError("message must not be empty")
        if len(message) > MAX_CHAT_CHARS:
            raise UserError(f"message is too long (limit {MAX_CHAT_CHARS} characters)")
        sid = row["id"]
        history = self.db.all("SELECT role, text FROM messages WHERE session_id=? ORDER BY id DESC LIMIT ?",
                              (sid, chat_mod.HISTORY_MESSAGES))[::-1]
        scan_id = self._latest_scan_id(sid)
        findings = self.db.load_findings(scan_id, with_masks=True) if scan_id else []
        files = list(self._manifest(sid))
        from harness import intent
        from harness.llm import LLMError
        try:
            decision = await intent.decide(self.llm, message, row, files, scan_id is not None,
                                           self.scans.is_running(sid), history)
            if decision["action"] in ("none", "summary"):
                ws = chat_mod.Workspace(self.code_dir(sid), findings)
                if decision["action"] == "summary":
                    reply, ids = await chat_mod.summarize(self.llm, ws)
                else:
                    reply, ids = await chat_mod.chat(self.llm, ws, message, history, self.cfg.llm_tool_calling)
                action = None
            elif decision["action"] == "fix":
                reply, action = self._fix_reply(row, message, findings)
                ids = action["finding_ids"] if action else []
            else:
                reply, action = self._action_reply(row, decision, files)
                ids = []
        except LLMError as e:
            raise UserError(str(e)) from e
        ts = now()
        self.db.many("INSERT INTO messages (session_id, role, text, finding_ids, created_at) VALUES (?,?,?,?,?)",
                     [(sid, "user", message, "[]", ts), (sid, "assistant", reply, json.dumps(ids), ts)])
        self.db.run("UPDATE sessions SET updated_at=? WHERE id=?", (ts, sid))
        return {"reply": reply, "finding_ids": ids, "action": action}

    def _action_reply(self, row, d, files):
        """Turn the intent decision into the chat reply and the action for the extension to carry out."""
        from harness import intent
        running = self.scans.is_running(row["id"])
        if d["action"] == "cancel":
            if not running:
                return "No scan is running right now.", None
            return "Stopping the scan.", _action("cancel")
        if running:
            return "A scan is already running. I'll show the results when it finishes, or say \"stop\" to cancel it.", None

        if d["action"] == "scan_github":
            from harness import github
            try:
                owner, repo = github.parse_url(d["url"])
            except UserError:
                return ("I can only scan public GitHub repositories given as https://github.com/owner/repo. "
                        "Which repository should I scan?"), None
            url = f"https://github.com/{owner}/{repo}"
            text = f"Do you want me to scan {url}?" if not d["sure"] else f"Scanning {url}."
            return text, _action("scan_github", url=url, confirm=not d["sure"])

        # "scan" = this session's target; "scan_workspace" = the local workspace while in a GitHub session.
        kind = "scan_workspace" if d["action"] == "scan_workspace" and row["target_type"] == "github" else "scan"
        own_files = files if kind == "scan" else []  # the workspace's files are not known in a GitHub session
        if own_files:
            paths, unknown = intent.resolve_paths(d["paths"], own_files)
        else:  # nothing uploaded yet: pass the folders on; start_scan checks them after the upload
            paths = [str(p).strip().removeprefix("./").strip("/") for p in d["paths"] if str(p).strip("./ ")]
            unknown = []
        if unknown:
            folders = ", ".join(f"`{f}`" for f in intent.project_folders(files)[:12])
            return (f"I couldn't find {', '.join(repr(u) for u in unknown)} in this project. "
                    f"Which folder do you mean? Top folders: {folders}"), None
        if paths:
            what = ", ".join(f"`{p}`" for p in paths)
        elif kind == "scan" and row["target_type"] == "github":
            what = row["repo_url"]
        else:
            what = "the workspace"
        how = " from scratch" if d["full"] else ""
        text = f"Do you want me to scan {what}{how}?" if not d["sure"] else f"Starting a scan of {what}{how}."
        return text, _action(kind, full=d["full"], paths=paths, confirm=not d["sure"])

    def _fix_reply(self, row, message, findings):
        """Pick the findings a fix request means. The extension then runs fix_findings on them
        and shows the edits before changing any file."""
        if row["target_type"] != "workspace":
            return ("I can only fix files in your local workspace, so auto-fix does not work for a GitHub session. "
                    "Open the project in VS Code and ask me to scan it there."), None
        if self.scans.is_running(row["id"]):
            return "A scan is running. Ask me again when it has finished.", None
        if not findings:
            return "There are no findings to fix. Ask me to scan the project first.", None
        targets = fix_targets(message, findings)
        if not targets and re.search(r"(?i)\b(it|this|that|those|these|them)\b", message):
            # "fix it": the findings the last reply talked about
            last = self.db.one("SELECT finding_ids FROM messages WHERE session_id=? AND role='assistant' "
                               "ORDER BY id DESC LIMIT 1", (row["id"],))
            by_id = {f["id"]: f for f in findings}
            targets = [by_id[i] for i in json.loads(last["finding_ids"] or "[]") if i in by_id] if last else []
        if not targets:
            return ("Which findings should I fix? Name a finding id, a severity (\"fix all high findings\"), "
                    "or a file (\"fix src/db.py\"), or click **Fix** on a finding."), None
        chosen = targets[:MAX_FIX_BATCH]
        more = f" (the first {MAX_FIX_BATCH} of {len(targets)})" if len(targets) > MAX_FIX_BATCH else ""
        ids = [f["id"] for f in chosen]
        if len(chosen) == 1:
            return (f"Preparing a fix for `{chosen[0]['id']}` ({chosen[0]['title']}). "
                    "You'll see the change before it is applied."), _action("fix", finding_ids=ids)
        if len(chosen) <= ASK_BEFORE_FIXING_OVER:
            return (f"Preparing fixes for {len(chosen)} findings. "
                    "You'll see every change before it is applied."), _action("fix", finding_ids=ids)
        files = len({f["path"] for f in chosen})
        minutes = max(1, round(files * SECONDS_PER_FILE / max(1, self.cfg.llm_max_parallel) / 60))
        return (f"Fix {len(chosen)} findings{more} in {files} files? The fix agent takes about {minutes} "
                f"minute{'s' if minutes > 1 else ''}. When it is done you can apply all changes at once or review "
                "each file first."), \
            _action("fix", finding_ids=ids, confirm=True)

    async def summarize_findings(self, user, session_id):
        """A short summary of the latest scan's findings. Not saved in the chat history."""
        row = self._session(user, session_id)
        scan_id = self._latest_scan_id(row["id"])
        findings = self.db.load_findings(scan_id, with_masks=True) if scan_id else []
        summary, ids = await chat_mod.summarize(self.llm, chat_mod.Workspace(self.code_dir(row["id"]), findings))
        return {"summary": summary, "finding_ids": ids}

    async def fix_findings(self, user, session_id, finding_ids, report):
        """Run the fix agent on findings of the latest scan. Sends progress through `report`
        (with a heartbeat), and returns line edits per file; nothing is changed on disk."""
        from harness import agent
        from harness.llm import LLMError
        row = self._session(user, session_id)
        if row["target_type"] != "workspace":
            raise UserError("auto-fix works only for workspace sessions")
        if self.scans.is_running(row["id"]):
            raise UserError("a scan is running; fix findings after it finishes")
        scan_id = self._latest_scan_id(row["id"])
        findings = self.db.load_findings(scan_id, with_masks=True) if scan_id else []
        by_id = {f["id"]: f for f in findings}
        ids = list(dict.fromkeys(str(i) for i in finding_ids or []))
        if not ids:
            raise UserError("no findings given")
        if len(ids) > MAX_FIX_BATCH:
            raise UserError(f"at most {MAX_FIX_BATCH} findings at a time")
        missing = [i for i in ids if i not in by_id]
        if missing:
            raise UserError(f"finding not found: {missing[0]}")

        last = {"percent": 0}

        async def progress(percent, message):
            last["percent"] = percent
            await report(percent, message)

        async def heartbeat():  # keeps the client's timeout from firing; clients ignore this event
            while True:
                await asyncio.sleep(10)
                await report(last["percent"], json.dumps({"file": None, "kind": "heartbeat", "text": ""}))

        beat = asyncio.create_task(heartbeat())
        try:
            return await agent.fix_findings(self.llm, self.cfg, self.code_dir(row["id"]),
                                            [by_id[i] for i in ids], findings, progress)
        except LLMError as e:
            raise UserError(str(e)) from e
        finally:
            beat.cancel()


def _action(type_, full=False, paths=(), url=None, confirm=False, finding_ids=()):
    return {"type": type_, "full": full, "paths": list(paths), "url": url, "confirm": confirm,
            "finding_ids": list(finding_ids)}


_SEVERITY_WORDS = {"critical": "critical", "crit": "critical", "high": "high", "medium": "medium", "med": "medium",
                   "low": "low", "info": "info"}


def fix_targets(message, findings):
    """Findings a fix request names: ids, else severities and files (likely false alarms left out).
    "fix everything" means every finding that is not a likely false alarm. Most serious first."""
    by_id = {f["id"]: f for f in findings}
    ids = [i for i in re.findall(r"[0-9a-f]{32}", message) if i in by_id]
    if ids:
        return [by_id[i] for i in dict.fromkeys(ids)]
    low = message.lower()
    words = set(re.findall(r"[a-z]+", low))
    sevs = {_SEVERITY_WORDS[w] for w in words if w in _SEVERITY_WORDS}
    tokens = set(re.findall(r"[\w./-]+", message))
    paths = {f["path"] for f in findings
             if f["path"] in tokens or (len(f["path"].rsplit("/", 1)[-1]) > 3 and f["path"].rsplit("/", 1)[-1] in tokens)}
    if not sevs and not paths and not words & {"all", "every", "everything"}:
        return []
    out = [f for f in findings if f["verdict"] != "likely_false_positive"
           and (not sevs or f["severity"] in sevs) and (not paths or f["path"] in paths)]
    return sorted(out, key=lambda f: (SEVERITIES.index(f["severity"]), f["verdict"] != "likely_real",
                                      f["path"], f["start_line"]))
