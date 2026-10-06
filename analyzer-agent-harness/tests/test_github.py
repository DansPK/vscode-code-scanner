import shutil
import subprocess

import pytest

from conftest import FIXTURE, needs_scanners
from harness.service import UserError
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


async def test_private_repo_token_goes_to_git_only_as_an_env_header(cfg, monkeypatch, tmp_path):
    import base64
    from harness import github, proc
    calls = []

    async def fake_run(args, cwd=None, env=None, **kw):
        calls.append((args, env or {}))
        if args[1] == "clone":
            (tmp_path / "code" / ".git").mkdir(parents=True)
            (tmp_path / "code" / "a.py").write_text("x = 1\n")
        return 0, "abc123", ""
    monkeypatch.setattr(proc, "run", fake_run)
    token = "ghp_" + "A1b2C3d4" * 4
    gh = github.GitHub(cfg)
    session = {"id": "s", "repo_url": "https://github.com/acme/private-app"}
    files, _, web = await gh.prepare(session, tmp_path / "code", token)
    assert files == ["a.py"] and web == "https://github.com/acme/private-app/blob/abc123"
    clone_args, clone_env = next(c for c in calls if c[0][1] == "clone")
    assert token not in " ".join(clone_args)  # never on the command line
    assert clone_env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraheader"
    assert base64.b64decode(clone_env["GIT_CONFIG_VALUE_0"].split()[-1]).decode() == f"x-access-token:{token}"
    rev_env = next(c for c in calls if c[0][1] == "rev-parse")[1]
    assert "GIT_CONFIG_VALUE_0" not in rev_env  # local commands never get it

    for bad in ["short", "ghp_abc\r\nX-Evil: 1" + "a" * 20, "a b" * 10]:
        with pytest.raises(UserError, match="token is not valid"):
            await gh.prepare(session, tmp_path / "code2", bad)


async def test_failed_clone_suggests_signing_in(cfg, monkeypatch, tmp_path):
    from harness import github, proc

    async def failing(args, **kw):
        return 128, "", "fatal: could not read Username for 'https://github.com'"
    monkeypatch.setattr(proc, "run", failing)
    gh = github.GitHub(cfg)
    session = {"id": "s", "repo_url": "https://github.com/acme/private-app"}
    with pytest.raises(UserError, match="If the repository is private, sign in to GitHub"):
        await gh.prepare(session, tmp_path / "c1")
    with pytest.raises(UserError, match="with your GitHub sign-in"):
        await gh.prepare(session, tmp_path / "c2", "ghp_" + "x" * 36)
