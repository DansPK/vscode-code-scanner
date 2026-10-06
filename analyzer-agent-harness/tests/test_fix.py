import json

import pytest

from conftest import needs_scanners
from fakes import FakeLLMCompletion
from flow import sync_upload_scan
from harness import chat, fix, intent
from harness.llm import LLM
from harness.service import fix_targets
from mcp_client import call, connect

LINES = [f"line {i}" for i in range(1, 41)]
RANGES = [(1, 40)]


def edits(*items, explanation="Done."):
    return json.dumps({"edits": [{"start_line": a, "end_line": b, "replacement": r} for a, b, r in items],
                       "explanation": explanation})


def test_parse_checks_the_edits():
    got, why = fix.parse(edits((3, 4, "new 3"), (1, 1, "new 1")), LINES, RANGES, [])
    assert [e["start_line"] for e in got] == [1, 3] and why == "Done."
    # a single edit without the list, with fences and copied line numbers
    one = '{"start_line": 2, "end_line": 2, "replacement": "```python\\n    2 | fixed\\n```"}'
    assert fix.parse(one, LINES, RANGES, [])[0] == [{"start_line": 2, "end_line": 2, "replacement": "fixed"}]
    for bad, reason in [("no json", "not JSON"), (edits((39, 45, "x")), "not all shown"),
                        (edits((1, 3, "a"), (3, 4, "b")), "overlap"), (edits((2, 2, "line 2")), "change nothing"),
                        ('{"edits": []}', "no edits")]:
        with pytest.raises(fix.FixError, match=reason):
            fix.parse(bad, LINES, RANGES, [])
    # lines between the header and the window were not shown
    with pytest.raises(fix.FixError, match="not all shown"):
        fix.parse(edits((20, 20, "x")), LINES, [(1, 15), (25, 40)], [])


def test_parse_refuses_to_copy_a_hidden_secret():
    masks = [(5, 10, 5, 30)]
    with pytest.raises(fix.FixError, match="hidden secret"):
        fix.parse(edits((5, 5, 'KEY = "sk_l****************"')), LINES, RANGES, masks)
    got, _ = fix.parse(edits((5, 5, 'KEY = os.environ["KEY"]')), LINES, RANGES, masks)
    assert got[0]["replacement"] == 'KEY = os.environ["KEY"]'


async def test_propose_masks_secrets_and_retries_once(cfg, tmp_path):
    (tmp_path / "config.py").write_text('import os\nKEY = "sk_live_abcdefghijklmnop"\n')
    finding = {"id": "f" * 32, "path": "config.py", "start_line": 2, "end_line": 2, "title": "Secret",
               "severity": "high", "cwe": "CWE-798", "rule_id": "r", "message": "m", "_mask": [(2, 8, 2, 31)]}
    fake = FakeLLMCompletion(replies=["not json", edits((2, 2, 'KEY = os.environ["KEY"]'))])
    p = await fix.propose(LLM(cfg, fake), finding, tmp_path)
    assert p["edits"] == [{"start_line": 2, "end_line": 2, "replacement": 'KEY = os.environ["KEY"]'}]
    assert len(p["file_sha256"]) == 64 and p["path"] == "config.py"
    prompt = fake.calls[0]["messages"][1]["content"]
    assert "sk_live_abcdefghijklmnop" not in prompt and "sk_l****" in prompt
    assert len(fake.calls) == 2  # one retry after the bad reply

    fake = FakeLLMCompletion(replies=["nope", "still nope"])
    with pytest.raises(fix.FixError, match="could not produce a usable fix"):
        await fix.propose(LLM(cfg, fake), finding, tmp_path)


def _f(id_, severity, path, verdict="likely_real"):
    return {"id": id_ * 32, "severity": severity, "path": path, "start_line": 1, "verdict": verdict, "title": "t"}


def test_fix_targets():
    fs = [_f("a", "high", "src/db.py"), _f("b", "low", "src/db.py"), _f("c", "high", "app.py"),
          _f("d", "critical", "app.py", "likely_false_positive")]
    ids = lambda msg: [f["id"][0] for f in fix_targets(msg, fs)]
    assert ids("fix all high findings") == ["c", "a"]
    assert ids("fix src/db.py") == ["a", "b"]
    assert ids("fix the high ones in db.py") == ["a"]
    assert ids("fix everything") == ["c", "a", "b"]  # most serious first, false alarms left out
    assert ids(f"fix {'d' * 32}") == ["d"]  # named explicitly, so included
    assert ids("fix it") == []


async def test_plain_commands_skip_the_model(cfg):
    fake = FakeLLMCompletion(intents=[{"action": "fix"}])
    llm = LLM(cfg, fake)
    session = {"target_type": "workspace", "repo_url": None}
    assert (await intent.decide(llm, "Summarize all findings", session, [], True, False))["action"] == "summary"
    assert (await intent.decide(llm, "fix all high findings", session, [], True, False))["action"] == "fix"
    assert not fake.intent_calls
    # "how do I fix" is a question, whatever the model says
    assert (await intent.decide(llm, "how do I fix the SQL injection?", session, [], True, False))["action"] == "none"


def test_summary_stats():
    fs = [{**_f("a", "high", "db.py"), "tools": ["semgrep"], "cwe": "CWE-89", "title": "SQL injection"},
          {**_f("b", "high", "db.py", "likely_false_positive"), "tools": ["semgrep", "sonarqube"], "cwe": "CWE-89",
           "title": "SQL injection"},
          {**_f("c", "low", "app.py"), "tools": ["semgrep"], "cwe": None, "title": "Debug"}]
    assert chat.summary_stats(fs) == ("**3 findings** (2 high · 1 low). 2 look real, 1 looks like false alarms.\n"
                                      "Most affected: `db.py` (1), `app.py` (1).")
    assert chat.summary_stats([]) == "**No findings.**"
    assert chat.summary_stats(fs[1:2]) == "**1 finding** (1 high). It looks like a false alarm."
    assert chat.summary_stats([fs[1], fs[1]]).endswith("All look like false alarms.")


def test_summary_is_cut_to_one_sentence_and_three_bullets():
    text = ("## Overall: The project is risky. It has SQL injection.\n\n## Top risks\n- a\n- b\n"
            "## Fix first\n1. c\n2. d\nNotes on risk scoring: 0.8")
    assert chat._parse_summary(text) == ("The project is risky.", ["a", "b", "c"])
    assert chat._parse_summary("Just one sentence. And more.") == ("Just one sentence.", [])


async def test_summary_skips_the_llm_when_nothing_looks_real(cfg, tmp_path):
    fake = FakeLLMCompletion()
    fs = [{**_f("a", "medium", "x.py", "likely_false_positive"), "tools": ["semgrep"], "cwe": None, "title": "t"}]
    text, ids, card = await chat.summarize(LLM(cfg, fake), chat.Workspace(tmp_path, fs))
    assert text.startswith("**1 finding**") and not fake.calls and ids == []
    assert card == {"total": 1, "counts": {"medium": 1}, "likely_real": 0, "false_alarms": 1, "files": [],
                    "overall": None, "fix_first": []}


def _scripted(*steps):
    """A fake LLM that answers the agent with the given tool calls, one step per call."""
    calls = []

    def fn(messages, tools):
        calls.append(list(messages))
        name, args = steps[len(calls) - 1]
        return {"content": "", "tool_calls": [{"id": f"c{len(calls)}", "name": name, "arguments": json.dumps(args)}]}
    return fn, calls


@needs_scanners
async def test_fix_agent_and_summary_through_mcp(harness_server, tokens, vuln_app):
    llm = harness_server.llm
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        await sync_upload_scan(c, sid, vuln_app)
        findings = (await call(c, "get_findings", {"session_id": sid}))["findings"]
        sqli = next(f for f in findings if f["path"] == "db.py" and "sql" in (f["title"] + f["rule_id"]).lower()
                    and f["tools"] == ["semgrep"])

        r = await call(c, "chat", {"session_id": sid, "message": "fix db.py"})
        assert r["action"]["type"] == "fix" and sqli["id"] in r["action"]["finding_ids"]

        llm.fn, seen = _scripted(
            ("read_file", {"path": "db.py"}),
            ("edit_file", {"path": "db.py",
                           "old_text": "cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")",
                           "new_text": "cur.execute(\"SELECT * FROM users WHERE name = ?\", (name,))"}),
            ("check_fixes", {}),
            ("finish", {"summary": "Used a parameterised query.", "fixed": [sqli["id"]]}))
        events = []

        async def on_progress(p, t, m):
            events.append(m or "")
        res = await call(c, "fix_findings", {"session_id": sid, "finding_ids": [sqli["id"]]},
                         progress_callback=on_progress)
        llm.fn = None
        assert [f["path"] for f in res["files"]] == ["db.py"] and res["files"][0]["file_sha256"] == sqli["file_sha256"]
        assert "?\", (name,))" in res["files"][0]["edits"][0]["replacement"]
        outcome = next(o for o in res["results"] if o["finding_id"] == sqli["id"])
        assert outcome["status"] == "fixed", outcome  # Semgrep reran with that rule and no longer fires
        assert "no longer reported" in seen[3][-1]["content"]  # what check_fixes told the agent
        assert "Used a parameterised query." in res["summary"]
        events = [json.loads(e) for e in events]
        assert {"file": "db.py", "kind": "tool", "text": "Edit db.py"} in events
        assert {"file": "db.py", "kind": "result", "text": "+1 −1 lines"} in events
        assert any(e["kind"] == "result" and "no longer reported" in e["text"] for e in events)
        assert all(e["kind"] != "text" or e["text"] for e in events)
        with pytest.raises(RuntimeError, match="finding not found"):
            await call(c, "fix_findings", {"session_id": sid, "finding_ids": ["0" * 32]})

        llm.replies = ["Overall: Risky.\n- Fix `%s` in db.py" % sqli["id"]] * 2
        r = await call(c, "chat", {"session_id": sid, "message": "summarize all findings"})
        assert r["reply"].startswith(f"**{len(findings)} findings**") and "**Fix first:**" in r["reply"]
        assert r["finding_ids"] == [sqli["id"]] and r["action"] is None
        before = len((await call(c, "get_session", {"session_id": sid}))["messages"])
        s = await call(c, "summarize_findings", {"session_id": sid})
        assert s["summary"] == r["reply"] and s["finding_ids"] == [sqli["id"]]
        card = s["card"]
        assert card["total"] == len(findings) and card["overall"] == "Risky."
        assert card["fix_first"] == [{"text": "Fix in db.py", "finding_ids": [sqli["id"]]}]  # id moved out of the text
        assert sum(card["counts"].values()) == len(findings) and card["files"]
        assert len((await call(c, "get_session", {"session_id": sid}))["messages"]) == before  # not in history

    async with connect(harness_server.url, tokens["bob"]) as c:  # other users cannot fix alice's findings
        with pytest.raises(RuntimeError, match="session not found"):
            await call(c, "fix_findings", {"session_id": sid, "finding_ids": [sqli["id"]]})


async def test_fix_all_asks_first_for_big_batches(harness_server, tokens):
    from harness.service import ASK_BEFORE_FIXING_OVER
    svc = harness_server.service
    row = {"id": "s", "target_type": "workspace"}
    fs = [{**_f(f"{i:x}", "high", f"f{i}.py"), "id": f"{i:032x}"} for i in range(25)]
    svc.scans.is_running = lambda sid: False
    text, action = svc._fix_reply(row, "fix all vulnerabilities", fs)
    assert len(action["finding_ids"]) == 25 and action["confirm"] is True and "Fix 25 findings in 25 files?" in text
    text, action = svc._fix_reply(row, "fix all vulnerabilities", fs[:ASK_BEFORE_FIXING_OVER])
    assert action["confirm"] is False and "Preparing fixes" in text


def _apply(orig, edits):
    out = list(orig)
    for e in sorted(edits, key=lambda e: -e["start_line"]):
        out[e["start_line"] - 1:e["end_line"]] = e["replacement"].split("\n") if e["replacement"] else []
    return out


def test_line_edits_rebuild_the_new_file():
    from harness.agent import line_edits
    a = ["import os", "", "def f():", "    x = 1", "    return x"]
    for new in [["import os", "import sys", "", "def f():", "    x = 1", "    return x"],  # insert in the middle
                ["# header", "import os", "", "def f():", "    x = 1", "    return x"],  # insert at the top
                a + ["", "print(f())"],                                                 # append
                ["import os", "def f():", "    return 1"],                              # delete and replace
                ["import os", "import sys", "", "def f():", "    y = 2", "    return x"],  # two nearby changes
                ["", "", "def f():", "    x = 1", "    return x"],                       # a line becomes blank
                ["import os", "", "def f():", "    x = 1", ""]]:                          # last line becomes blank
        edits = line_edits(a, new)
        assert _apply(a, edits) == new, (new, edits)
        assert all(e["start_line"] <= e["end_line"] for e in edits)
        assert all(x["end_line"] < y["start_line"] for x, y in zip(edits, edits[1:]))


def test_edit_tool_is_exact_unique_and_keeps_secrets(tmp_path):
    from harness.agent import AgentError, Edits
    (tmp_path / "a.py").write_text('KEY = "sk_live_abcdefghijklmnop"\nx = 1\nx = 1\ny = 2\n')
    ed = Edits(tmp_path, {"a.py": [(1, 8, 1, 31)]})
    view = ed.read("a.py")
    assert "sk_live_abcdefghijklmnop" not in view and "sk_l****" in view
    for old, new, err in [("x = 1", "x = 2", "appears 2 times"), ("nope", "", "not found"),
                          ('KEY = "sk_l', 'KEY = "sk_l', "hidden secret")]:
        with pytest.raises(AgentError, match=err):
            ed.edit("a.py", old, new)
    with pytest.raises(AgentError, match="invalid path"):
        ed.read("../etc/passwd")
    ed.edit("a.py", "x = 1\ny = 2", "x = 1\ny = 3")
    line = next(l for l in ed.read("a.py").splitlines() if "KEY" in l)
    ed.edit("a.py", line.split("| ", 1)[1], 'KEY = os.environ["KEY"]')
    assert ed.files["a.py"]["real"] == ['KEY = os.environ["KEY"]', "x = 1", "x = 1", "y = 3"]
    p = ed.proposals()[0]
    assert p["path"] == "a.py" and _apply(ed.files["a.py"]["orig"], p["edits"]) == ed.files["a.py"]["real"]


async def test_agent_falls_back_to_one_shot_fixes(cfg, tmp_path):
    from harness import agent
    (tmp_path / "db.py").write_text("q = 'a' + x\nrun(q)\n")
    t = {"id": "a" * 32, "path": "db.py", "start_line": 1, "end_line": 1, "title": "SQL", "severity": "high",
         "cwe": None, "rule_id": "r", "message": "m", "tools": ["semgrep"]}
    fake = FakeLLMCompletion(replies=["I would fix it like this.", edits((1, 1, "q = ('a', x)"))])
    events = []

    async def report(p, m):
        events.append(m)
    res = await agent.fix_findings(LLM(cfg, fake), cfg, tmp_path, [t], [t], report)
    assert res["files"][0]["edits"] == [{"start_line": 1, "end_line": 1, "replacement": "q = ('a', x)"}]
    assert fake.calls[0]["tools"] and not fake.calls[1]["tools"]  # agent first, then the one-shot fix
    events = [json.loads(e) for e in events]
    assert {"file": "db.py", "kind": "text", "text": "I would fix it like this."} in events  # streamed text
    assert any(e["kind"] == "status" and "one-shot" in e["text"] for e in events)


def test_small_files_go_into_the_task_whole(tmp_path):
    from harness.agent import WHOLE_FILE_LINES, Edits, _task
    (tmp_path / "small.py").write_text("".join(f"x{i} = {i}\n" for i in range(1, 51)))
    (tmp_path / "big.py").write_text("".join(f"y{i} = {i}\n" for i in range(1, WHOLE_FILE_LINES + 50)))
    t = lambda p, line: {"id": "a" * 32, "path": p, "start_line": line, "end_line": line, "title": "T",
                         "severity": "high", "cwe": None, "tools": ["semgrep"], "message": "m"}
    ed = Edits(tmp_path, {})
    small = _task(ed, [t("small.py", 25)], 100_000)
    assert "The whole of small.py" in small and "x1 = 1" in small and "x50 = 50" in small
    big = _task(ed, [t("big.py", 200)], 100_000)
    assert "The whole of" not in big and "y200 = 200" in big and "y1 = 1\n" not in big
