import threading

import pytest

from conftest import Server, needs_scanners
from flow import sync_upload_scan
from mcp_client import call, connect


@needs_scanners
async def test_full_flow_then_incremental_rescan(harness_server, tokens, vuln_app, cfg):
    url = harness_server.url
    async with connect(url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"target_type": "workspace", "name": "demo"}))["session_id"]

        # First scan: everything is needed.
        s, summary, events = await sync_upload_scan(c, sid, vuln_app)
        assert sorted(s["need"]) == ["auth.py", "config.py", "db.py", "tools.py"] and s["delete"] == []
        assert summary["status"] == "done", summary
        assert summary["stage"] == "finished" and summary["percent"] == 100
        assert "sonarqube" in (summary["error"] or "")  # no SonarQube in tests; scan still done
        assert events and all(t == 100 for _, t, _ in events)
        assert any("Semgrep" in m for _, _, m in events)
        first = await call(c, "get_findings", {"session_id": sid})
        assert first["total"] == len(first["findings"]) > 0
        assert {f["path"] for f in first["findings"]} == {"auth.py", "config.py", "db.py", "tools.py"}
        assert all(f["verdict"] == "likely_real" and f["explanation"] for f in first["findings"])
        assert all(f["status"] == "new" for f in first["findings"])
        assert sum(summary["counts"].values()) == first["total"]

        # Filters and paging
        high = await call(c, "get_findings", {"session_id": sid, "severity": ["high"]})
        assert high["total"] and all(f["severity"] == "high" for f in high["findings"])
        page = await call(c, "get_findings", {"session_id": sid, "limit": 2, "offset": 1})
        assert len(page["findings"]) == 2 and page["findings"][0] == first["findings"][1]
        assert (await call(c, "get_findings", {"session_id": sid, "path": "db.py"}))["total"] >= 1

        # Edit one file, delete another.
        (vuln_app / "db.py").write_text((vuln_app / "db.py").read_text().replace(
            '''cur.execute("SELECT * FROM users WHERE name = '" + name + "'")''',
            '''cur.execute("SELECT * FROM users WHERE name = ?", (name,))'''))
        (vuln_app / "auth.py").unlink()
        reviews_before = len(harness_server.llm.calls)
        s2, summary2, _ = await sync_upload_scan(c, sid, vuln_app)
        assert s2["need"] == ["db.py"] and s2["delete"] == ["auth.py"] and s2["unchanged_count"] == 2
        assert summary2["status"] == "done"
        second = await call(c, "get_findings", {"session_id": sid})
        paths = {f["path"] for f in second["findings"]}
        assert "auth.py" not in paths
        before = {f["id"]: f for f in first["findings"] if f["path"] in ("config.py", "tools.py")}
        kept = {f["id"]: f for f in second["findings"] if f["path"] in ("config.py", "tools.py")}
        assert before.keys() == kept.keys()
        assert all(f["status"] == "existing" for f in kept.values())
        old_db = {f["id"] for f in first["findings"] if f["path"] == "db.py"}
        new_db = {f["id"] for f in second["findings"] if f["path"] == "db.py"}
        assert new_db != old_db
        # Only findings that are new to the cache went to the LLM.
        assert len(harness_server.llm.calls) - reviews_before == len(new_db - old_db)

        # Nothing changed: nothing to upload.
        s3 = await call(c, "sync_files", {"session_id": sid, "manifest": __import__("flow").manifest(vuln_app)})
        assert s3["need"] == [] and s3["delete"] == []

        info = await call(c, "get_session", {"session_id": sid})
        assert info["file_count"] == 3 and info["latest_scan_id"]
        assert info["session"]["last_scan_status"] == "done"


@needs_scanners
async def test_only_one_scan_at_a_time_and_cancel(harness_server, tokens, vuln_app):
    import asyncio

    async def slow(messages, tools=None):  # hold the scan in the LLM step until cancelled
        await asyncio.sleep(3600)
        return {"content": "{}", "tool_calls": []}

    harness_server.service.llm._completion = slow
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        from flow import archive, manifest, upload
        s = await call(c, "sync_files", {"session_id": sid, "manifest": manifest(vuln_app)})
        up, _ = await upload(c, sid, archive(vuln_app, s["need"]))
        scan = await call(c, "start_scan", {"session_id": sid, "upload_id": up["upload_id"]})
        with pytest.raises(RuntimeError, match="already running"):
            await call(c, "start_scan", {"session_id": sid})
        assert (await call(c, "cancel_scan", {"scan_id": scan["scan_id"]}))["ok"] is True
        st = await call(c, "get_scan_status", {"scan_id": scan["scan_id"]})
        assert st["status"] == "cancelled"


async def test_users_cannot_see_each_other(server, tokens):
    async with connect(server, tokens["alice"]) as a, connect(server, tokens["bob"]) as b:
        sid = (await call(a, "create_session", {"name": "mine"}))["session_id"]
        for tool, args in [("get_session", {"session_id": sid}), ("rename_session", {"session_id": sid, "name": "x"}),
                           ("delete_session", {"session_id": sid}), ("get_findings", {"session_id": sid}),
                           ("chat", {"session_id": sid, "message": "hi"}),
                           ("sync_files", {"session_id": sid, "manifest": []})]:
            with pytest.raises(RuntimeError, match="session not found"):
                await call(b, tool, args)
        assert (await call(b, "list_sessions"))["sessions"] == []
        assert [s["name"] for s in (await call(a, "list_sessions"))["sessions"]] == ["mine"]


async def test_session_crud_and_chat(harness_server, tokens):
    harness_server.llm.replies = ["Hello! No scan yet."]
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {"name": "one"}))["session_id"]
        await call(c, "rename_session", {"session_id": sid, "name": "two"})
        r = await call(c, "chat", {"session_id": sid, "message": "hi there"})
        assert r == {"reply": "Hello! No scan yet.", "finding_ids": [], "action": None}
        info = await call(c, "get_session", {"session_id": sid})
        assert info["session"]["name"] == "two"
        assert [(m["role"], m["text"]) for m in info["messages"]] == [("user", "hi there"),
                                                                      ("assistant", "Hello! No scan yet.")]
        with pytest.raises(RuntimeError, match="too long"):
            await call(c, "chat", {"session_id": sid, "message": "x" * 9000})
        await call(c, "delete_session", {"session_id": sid})
        assert harness_server.sonar.deleted == [f"harness-{sid}"]
        assert not (harness_server.cfg.sessions_dir / sid).exists()
        with pytest.raises(RuntimeError, match="session not found"):
            await call(c, "get_session", {"session_id": sid})


@needs_scanners
async def test_restart_keeps_everything(cfg, tokens, vuln_app):
    s1 = Server(cfg)
    try:
        async with connect(s1.url, tokens["alice"]) as c:
            sid = (await call(c, "create_session", {"name": "keep"}))["session_id"]
            await sync_upload_scan(c, sid, vuln_app)
            s1.llm.replies = ["noted"]
            await call(c, "chat", {"session_id": sid, "message": "remember me"})
            before = await call(c, "get_findings", {"session_id": sid})
    finally:
        s1.stop()
    s2 = Server(cfg)  # same data folder
    try:
        async with connect(s2.url, tokens["alice"]) as c:
            info = await call(c, "get_session", {"session_id": sid})
            assert info["session"]["name"] == "keep" and len(info["messages"]) == 2
            assert await call(c, "get_findings", {"session_id": sid}) == before
    finally:
        s2.stop()


async def test_bad_manifest_paths_refused(server, tokens):
    async with connect(server, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        for bad in ["../x", "/etc/passwd", "a//b", "a\\b", "./a", "a/./b", ""]:
            with pytest.raises(RuntimeError):
                await call(c, "sync_files", {"session_id": sid,
                                             "manifest": [{"path": bad, "sha256": "0" * 64, "size": 1}]})


@needs_scanners
async def test_watch_sends_heartbeats(harness_server, tokens, vuln_app, monkeypatch):
    import asyncio
    from harness import scans
    monkeypatch.setattr(scans, "HEARTBEAT_SECONDS", 0.2)
    gate = threading.Event()  # the server runs in another thread and loop

    async def slow(messages, tools=None):
        while not gate.is_set():
            await asyncio.sleep(0.05)
        from fakes import GOOD_REVIEW
        import json
        return {"content": json.dumps(GOOD_REVIEW), "tool_calls": []}

    harness_server.service.llm._completion = slow
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        from flow import archive, manifest, upload
        s = await call(c, "sync_files", {"session_id": sid, "manifest": manifest(vuln_app)})
        up, _ = await upload(c, sid, archive(vuln_app, s["need"]))
        scan = await call(c, "start_scan", {"session_id": sid, "upload_id": up["upload_id"]})
        events = []

        async def on_progress(p, t, m):
            events.append(m)
            if len(events) == 8:  # let the scan finish once heartbeats have been seen
                gate.set()

        summary = await call(c, "watch_scan", {"scan_id": scan["scan_id"]}, progress_callback=on_progress)
        assert summary["status"] == "done" and len(events) >= 8


@needs_scanners
async def test_findings_appear_while_the_scan_runs(harness_server, tokens, vuln_app):
    import asyncio
    import json
    from fakes import GOOD_REVIEW
    gate = threading.Event()
    reviewed = []

    async def slow(messages, tools=None):  # the first review goes through, then hold the rest
        if reviewed:
            while not gate.is_set():
                await asyncio.sleep(0.05)
        reviewed.append(1)
        return {"content": json.dumps(GOOD_REVIEW), "tool_calls": []}

    harness_server.service.llm._completion = slow
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        from flow import archive, manifest, upload
        s = await call(c, "sync_files", {"session_id": sid, "manifest": manifest(vuln_app)})
        up, _ = await upload(c, sid, archive(vuln_app, s["need"]))
        scan_id = (await call(c, "start_scan", {"session_id": sid, "upload_id": up["upload_id"]}))["scan_id"]
        for _ in range(200):
            st = await call(c, "get_scan_status", {"scan_id": scan_id})
            live = await call(c, "get_findings", {"session_id": sid, "scan_id": scan_id})
            if st["stage"] == "llm_review" and any(f["explanation"] for f in live["findings"]):
                break
            await asyncio.sleep(0.1)
        assert st["status"] == "running" and live["total"] > 1
        done_now = [f for f in live["findings"] if f["explanation"]]
        pending = [f for f in live["findings"] if not f["explanation"]]
        assert done_now and pending  # reviews appear one by one
        # The latest finished scan is still the default view (none yet).
        assert (await call(c, "get_findings", {"session_id": sid}))["total"] == 0
        gate.set()
        final = await call(c, "watch_scan", {"scan_id": scan_id})
        assert final["status"] == "done"
        after = await call(c, "get_findings", {"session_id": sid})
        assert after["total"] == live["total"] and all(f["explanation"] for f in after["findings"])
