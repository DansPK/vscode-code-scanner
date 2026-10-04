import shutil
import subprocess

import pytest

from conftest import FIXTURE, needs_scanners
from mcp_client import call, connect


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture
def local_repo(tmp_path):
    """A local git repo standing in for github.com/acme/app."""
    repo = tmp_path / "remote"
    shutil.copytree(FIXTURE, repo)
    (repo / "loop").symlink_to("/etc/passwd")
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "one")
    return repo


@pytest.fixture
def gh_server(harness_server, local_repo):
    harness_server.service.github.clone_url = lambda owner, repo: f"file://{local_repo}"
    return harness_server


@needs_scanners
async def test_github_scan_and_rescans(gh_server, tokens, local_repo):
    async with connect(gh_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"target_type": "github",
                                                 "repo_url": "https://github.com/acme/app.git"}))["session_id"]
        info = await call(c, "get_session", {"session_id": sid})
        assert info["session"]["repo_url"] == "https://github.com/acme/app" and info["session"]["name"] == "acme/app"
        with pytest.raises(RuntimeError, match="only for workspace"):
            await call(c, "sync_files", {"session_id": sid, "manifest": []})

        async def scan():
            s = await call(c, "start_scan", {"session_id": sid})
            events = []

            async def on_progress(p, t, m):
                events.append(m)
            summary = await call(c, "watch_scan", {"scan_id": s["scan_id"]}, progress_callback=on_progress)
            assert summary["status"] == "done", summary
            return (await call(c, "get_findings", {"session_id": sid}))["findings"], events

        first, _ = await scan()
        commit = gh_server.service.db.one("SELECT last_commit FROM sessions WHERE id=?", (sid,))["last_commit"]
        assert first and all(
            f["web_url"] == f"https://github.com/acme/app/blob/{commit}/{f['path']}#L{f['start_line']}-L{f['end_line']}"
            for f in first)
        code = gh_server.cfg.sessions_dir / sid / "code"
        assert not (code / "loop").exists()  # symlinks are removed
        assert (await call(c, "get_session", {"session_id": sid}))["file_count"] == 4

        # No new commits: nothing changed, findings kept.
        second, events = await scan()
        assert any("No files changed" in m for m in events)
        assert {f["id"] for f in second} == {f["id"] for f in first}

        # A new commit that removes a file: only the diff is rescanned.
        git(local_repo, "rm", "-q", "auth.py")
        git(local_repo, "commit", "-q", "-m", "two")
        third, _ = await scan()
        assert "auth.py" not in {f["path"] for f in third}
        assert {f["id"] for f in third} == {f["id"] for f in first if f["path"] != "auth.py"}


@pytest.mark.parametrize("url", [
    "https://gitlab.com/acme/app", "http://github.com/acme/app", "https://github.com/acme",
    "https://github.com/acme/app/tree/main", "https://github.com.evil.com/acme/app", "git@github.com:acme/app.git",
    "https://github.com/acme/..", "https://user:pw@github.com/acme/app", "file:///etc"])
async def test_bad_github_urls_refused(server, tokens, url):
    async with connect(server, tokens["alice"]) as c:
        with pytest.raises(RuntimeError, match="only https://github.com"):
            await call(c, "create_session", {"target_type": "github", "repo_url": url})


async def test_missing_repo_gives_clear_error(harness_server, tokens, tmp_path):
    harness_server.service.github.clone_url = lambda o, r: f"file://{tmp_path}/nope"
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"target_type": "github",
                                                 "repo_url": "https://github.com/acme/none"}))["session_id"]
        with pytest.raises(RuntimeError, match="Could not get acme/none"):
            await call(c, "start_scan", {"session_id": sid})


def _online():
    import socket
    try:
        socket.create_connection(("github.com", 443), timeout=3).close()
        return True
    except OSError:
        return False


@needs_scanners
@pytest.mark.skipif(not _online(), reason="no network")
async def test_real_public_repo(server, tokens):
    async with connect(server, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"target_type": "github",
                                                 "repo_url": "https://github.com/octocat/Hello-World"}))["session_id"]
        s = await call(c, "start_scan", {"session_id": sid})
        summary = await call(c, "watch_scan", {"scan_id": s["scan_id"]})
        assert summary["status"] == "done"
        assert (await call(c, "get_session", {"session_id": sid}))["file_count"] >= 1
