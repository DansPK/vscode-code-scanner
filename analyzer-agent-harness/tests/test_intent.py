import pytest

from conftest import needs_scanners
from flow import sync_upload_scan
from harness import intent
from mcp_client import call, connect

FILES = ["Kasephal-API/src/main/java/A.java", "Kasephal-UI/src/app/page.tsx", "Kasephal-UI/package.json", "README.md"]


def test_parse_is_lenient_and_strict_about_actions():
    assert intent.parse('{"action": "scan", "full": true, "paths": "src", "sure": false}') == \
        {"action": "scan", "full": True, "paths": ["src"], "url": None, "sure": False}
    assert intent.parse("{'action': 'cancel'}")["action"] == "cancel"
    assert intent.parse('{"action": "delete_everything"}') is None
    assert intent.parse("I think you want a scan") is None
    assert intent.parse('{"action": "scan"}')["sure"] is True  # missing "sure" counts as sure


def test_resolve_paths_maps_loose_names_to_real_folders():
    assert intent.resolve_paths(["Kasephal-API"], FILES) == (["Kasephal-API"], [])
    assert intent.resolve_paths(["./Kasephal-UI/src/"], FILES) == (["Kasephal-UI/src"], [])
    assert intent.resolve_paths(["api"], FILES) == (["Kasephal-API"], [])
    assert intent.resolve_paths(["backend"], FILES) == ([], ["backend"])
    assert intent.resolve_paths(["src"], FILES) == ([], ["src"])  # ambiguous: two src folders
    assert intent.resolve_paths(["../etc"], FILES) == ([], ["../etc"])


def test_project_folders():
    assert intent.project_folders(FILES)[:2] == ["Kasephal-API", "Kasephal-UI"]


async def test_chat_actions(harness_server, tokens):
    llm = harness_server.llm
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]

        async def say(text, decision):
            llm.intents.append(decision)
            return await call(c, "chat", {"session_id": sid, "message": text})

        r = await say("scan my code", {"action": "scan"})
        assert r["action"] == {"type": "scan", "full": False, "paths": [], "url": None, "confirm": False}
        assert r["reply"] == "Starting a scan of the workspace."

        r = await say("is my login code safe?", {"action": "scan", "sure": False})
        assert r["action"]["confirm"] is True and r["reply"].startswith("Do you want me to scan")

        r = await say("scan everything again from scratch", {"action": "scan", "full": True})
        assert r["action"]["full"] is True and "from scratch" in r["reply"]

        r = await say("scan only the backend", {"action": "scan", "paths": ["backend"]})
        assert r["action"]["paths"] == ["backend"]  # nothing uploaded yet: checked by start_scan later

        r = await say("look at https://github.com/acme/app.git", {"action": "scan_github",
                                                                  "url": "https://github.com/acme/app.git"})
        assert r["action"]["type"] == "scan_github" and r["action"]["url"] == "https://github.com/acme/app"

        r = await say("scan gitlab.com/x/y", {"action": "scan_github", "url": "https://gitlab.com/x/y"})
        assert r["action"] is None and "GitHub" in r["reply"]

        r = await say("stop", {"action": "cancel"})
        assert r["action"] is None and r["reply"] == "No scan is running right now."

        r = await say("what is XSS?", {"action": "none"})
        assert r["action"] is None and llm.calls  # went to the chat agent

        hist = (await call(c, "get_session", {"session_id": sid}))["messages"]
        assert hist[0]["text"] == "scan my code" and hist[1]["text"] == "Starting a scan of the workspace."
        # The routing call saw the session's state
        assert "A finished scan exists: no." in llm.intent_calls[0][0]["content"]


async def test_github_session_can_ask_for_the_workspace(harness_server, tokens):
    harness_server.llm.intents = [{"action": "scan_workspace"}, {"action": "scan"}]
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"target_type": "github",
                                                 "repo_url": "https://github.com/acme/app"}))["session_id"]
        r = await call(c, "chat", {"session_id": sid, "message": "scan my local project instead"})
        assert r["action"]["type"] == "scan_workspace"
        r = await call(c, "chat", {"session_id": sid, "message": "rescan"})
        assert r["action"]["type"] == "scan" and "https://github.com/acme/app" in r["reply"]


@needs_scanners
async def test_folder_scan_keeps_the_rest(harness_server, tokens, vuln_app):
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        await sync_upload_scan(c, sid, vuln_app)
        first = (await call(c, "get_findings", {"session_id": sid}))["findings"]

        with pytest.raises(RuntimeError, match="no files under 'backend'"):
            await call(c, "start_scan", {"session_id": sid, "paths": ["backend"]})

        scan = await call(c, "start_scan", {"session_id": sid, "paths": ["./tools.py"], "full": True})
        summary = await call(c, "watch_scan", {"scan_id": scan["scan_id"]})
        assert summary["status"] == "done"
        after = (await call(c, "get_findings", {"session_id": sid}))["findings"]
        assert {f["id"] for f in after} == {f["id"] for f in first}
        assert all(f["status"] == "existing" for f in after)


async def test_folders_the_user_never_named_are_dropped(cfg):
    from fakes import FakeLLMCompletion
    from harness.llm import LLM
    fake = FakeLLMCompletion(intents=[{"action": "scan", "paths": ["Kasephal-API"]},
                                      {"action": "scan", "paths": ["Kasephal-API"]}])
    session = {"target_type": "workspace", "repo_url": None}
    d = await intent.decide(LLM(cfg, fake), "scan this project", session, FILES, True, False)
    assert d["paths"] == []
    d = await intent.decide(LLM(cfg, fake), "only scan the backend api", session, FILES, True, False)
    assert d["paths"] == ["Kasephal-API"]
