"""GitHub sessions: shallow clone on the first scan, fetch and diff after that."""

import asyncio
import base64
import logging
import os
import re
import shutil
from pathlib import Path

from harness import proc
from harness.db import now
from harness.files import walk_files
from harness.scanners.findings import file_sha256

log = logging.getLogger(__name__)

TOKEN_RE = re.compile(r"^[A-Za-z0-9_.-]{20,255}$")  # GitHub tokens; also keeps anything out of the header
PRIVATE_HINT = "If the repository is private, sign in to GitHub and scan again."
URL_RE = re.compile(r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?$")


class GitError(Exception):
    pass


def parse_url(url):
    """Accept only https://github.com/<owner>/<repo>, with an optional .git ending."""
    from harness.service import UserError
    m = URL_RE.match(str(url or "").strip())
    if not m or m.group(2) in (".", ".."):
        raise UserError("only https://github.com/<owner>/<repo> links are supported")
    return m.group(1), m.group(2)


def _dir_size(root):
    """Size of the work tree, without .git."""
    total = 0
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for n in names:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                total += os.path.getsize(p)
    return total


def _remove_symlinks(root):
    """A repo can hold symlinks that point outside it. Scanners must never follow them."""
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for n in names + dirnames:
            p = os.path.join(dirpath, n)
            if os.path.islink(p):
                os.unlink(p)
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]


class GitHub:
    def __init__(self, cfg, db=None):
        self.cfg = cfg
        self.db = db

    def clone_url(self, owner, repo):
        return f"https://github.com/{owner}/{repo}.git"

    async def _git(self, *args, cwd=None, token=None):
        # Never prompt for credentials. A user's token goes in as an HTTP header through git's
        # environment config: not on the command line (visible in `ps`), not in .git/config, not logged.
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if token:
            basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
            env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                       GIT_CONFIG_VALUE_0=f"AUTHORIZATION: basic {basic}")
        try:
            rc, out, err = await proc.run(["git", *args], cwd=cwd, env=env,
                                          timeout=self.cfg.git_clone_timeout_seconds)
        except asyncio.TimeoutError as e:
            raise GitError("git timed out") from e
        if rc != 0:
            log.warning("git %s failed: %s", args[0], err.strip()[-300:])
            raise GitError(f"git {args[0]} failed")
        return out.strip()

    async def prepare(self, session, code_dir, token=None):
        """Clone or update the repo. Returns (all paths, changed paths, web base URL).
        `token`: the user's GitHub token for a private repo, used for this call only."""
        from harness.service import UserError
        owner, repo = parse_url(session["repo_url"])
        if token is not None and not TOKEN_RE.match(str(token)):
            raise UserError("the GitHub token is not valid")
        git = lambda *a, **kw: self._git(*a, token=token, **kw)
        url = self.clone_url(owner, repo)
        code_dir = Path(code_dir)
        try:
            if (code_dir / ".git").is_dir():
                old = await self._git("rev-parse", "HEAD", cwd=code_dir)
                await git("fetch", "--depth", "1", "--no-tags", "origin", "HEAD", cwd=code_dir)
                new = await self._git("rev-parse", "FETCH_HEAD", cwd=code_dir)
                changed = set()
                if new != old:
                    diff = await self._git("diff", "--name-only", "--no-renames", "-z", old, new, cwd=code_dir)
                    changed = {p for p in diff.split("\0") if p}
                    await self._git("reset", "--hard", "-q", new, cwd=code_dir)
                    await self._git("clean", "-fdxq", cwd=code_dir)
            else:
                if code_dir.exists():
                    shutil.rmtree(code_dir)
                code_dir.parent.mkdir(parents=True, exist_ok=True)
                await git("clone", "--depth", "1", "--single-branch", "--no-tags", "-q", url, str(code_dir))
                new = await self._git("rev-parse", "HEAD", cwd=code_dir)
                changed = None
        except GitError as e:
            if token:
                raise UserError(f"Could not get {owner}/{repo} from GitHub with your GitHub sign-in ({e}). "
                                "Check that your account can read it.") from e
            raise UserError(f"Could not get {owner}/{repo} from GitHub ({e}). {PRIVATE_HINT}") from e

        await asyncio.to_thread(_remove_symlinks, code_dir)
        limit = self.cfg.upload_max_unpacked_mb * 1024 * 1024
        if await asyncio.to_thread(_dir_size, code_dir) > limit:
            shutil.rmtree(code_dir, ignore_errors=True)
            raise UserError(f"the repository is larger than the limit of {self.cfg.upload_max_unpacked_mb} MB")

        files = sorted(walk_files(code_dir))
        if self.db is not None:
            entries = await asyncio.to_thread(
                lambda: [(session["id"], p, file_sha256(code_dir / p), (code_dir / p).stat().st_size) for p in files])
            with self.db.conn() as c:
                c.execute("DELETE FROM manifest_files WHERE session_id=?", (session["id"],))
                c.executemany("INSERT INTO manifest_files VALUES (?,?,?,?)", entries)
                c.execute("UPDATE sessions SET last_commit=?, updated_at=? WHERE id=?", (new, now(), session["id"]))
        present = set(files)
        changed = present if changed is None else changed & present
        return files, changed, f"https://github.com/{owner}/{repo}/blob/{new}"
