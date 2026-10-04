import json
import os

import pytest

from fakes import GOOD_REVIEW, FakeLLMCompletion
from harness import chat, db, llm
from harness.scanners.findings import make_finding


@pytest.fixture
def store(tmp_path):
    return db.DB(tmp_path / "h.db")


def _finding(code_dir, path="db.py", line=14):
    return make_finding("semgrep", "python.sqli", "SQL injection", "high", "CWE-89", path, line, line,
                        None, None, "tainted sql", code_dir)


async def test_review_fills_every_finding(vuln_app, cfg, store):
    fake = FakeLLMCompletion()
    fs = [_finding(vuln_app), _finding(vuln_app, "auth.py", 6)]
    n, err = await llm.review_findings(fs, vuln_app, llm.LLM(cfg, fake), store, 2)
    assert n == 2 and err is None and len(fake.calls) == 2
    for f in fs:
        assert f["verdict"] == "likely_real"
        assert f["explanation"] and f["fix_recommendation"] and f["suggested_patch"]
    prompt = fake.calls[0]["messages"][1]["content"]
    assert "cur.execute" in prompt and "   14 |" in prompt


async def test_bad_json_retries_once_then_unsure(vuln_app, cfg, store):
    fake = FakeLLMCompletion(["not json", "still {not json"])
    fs = [_finding(vuln_app)]
    await llm.review_findings(fs, vuln_app, llm.LLM(cfg, fake), store, 1)
    assert len(fake.calls) == 2
    assert "not valid JSON" in fake.calls[1]["messages"][-1]["content"]
    assert fs[0]["verdict"] == "unsure" and "failed" in fs[0]["explanation"]


async def test_retry_can_recover(vuln_app, cfg, store):
    fake = FakeLLMCompletion(["oops", "```json\n" + json.dumps(GOOD_REVIEW) + "\n```"])
    fs = [_finding(vuln_app)]
    await llm.review_findings(fs, vuln_app, llm.LLM(cfg, fake), store, 1)
    assert fs[0]["verdict"] == "likely_real"


async def test_second_run_uses_cache(vuln_app, cfg, store):
    fake = FakeLLMCompletion()
    await llm.review_findings([_finding(vuln_app)], vuln_app, llm.LLM(cfg, fake), store, 1)
    again = [_finding(vuln_app)]
    n, _ = await llm.review_findings(again, vuln_app, llm.LLM(cfg, fake), store, 1)
    assert n == 0 and len(fake.calls) == 1 and again[0]["verdict"] == "likely_real"


async def test_unreachable_llm_stops_early(vuln_app, cfg, store):
    calls = []

    async def down(messages, tools=None):
        calls.append(1)
        raise llm.LLMUnreachable("The LLM cannot be reached")

    fs = [_finding(vuln_app, line=i) for i in range(1, 6)]
    n, err = await llm.review_findings(fs, vuln_app, llm.LLM(cfg, down), store, 1)
    assert err and len(calls) == 1 and all(f["verdict"] == "unsure" for f in fs)


def test_context_is_cut_to_fit(vuln_app, cfg):
    from dataclasses import replace
    small = llm.LLM(replace(cfg, llm_context_tokens=100))  # floor of 2000 chars
    big = vuln_app / "big.py"
    big.write_text("\n".join("x = '" + "a" * 200 + "'" for _ in range(100)))
    text = llm.code_context(vuln_app, _finding(vuln_app, "big.py", 50), small.max_code_chars)
    assert len(text) <= small.max_code_chars and "   50 |" in text


def test_review_masks_secrets(vuln_app):
    f = _finding(vuln_app, "config.py", 2)
    f["_mask"] = [(2, 19, 2, 70)]
    text = llm.code_context(vuln_app, f, 10_000)
    assert "sk_live_51HxQz8Kd93kfJd8s7Hq2LmNpQ4rStUvWxYz012345" not in text


# --- chat agent ---

def test_read_file_stays_inside(vuln_app, tmp_path):
    ws = chat.Workspace(vuln_app, [])
    (tmp_path / "outside.txt").write_text("top secret")
    os.symlink(tmp_path / "outside.txt", vuln_app / "link.txt")
    for bad in ["../outside.txt", "/etc/passwd", "a/../../outside.txt", "link.txt", "", "./db.py"]:
        assert "error" in ws.read_file(bad), bad
    assert "cur.execute" in ws.read_file("db.py")["text"]


def test_search_code(vuln_app):
    hits = chat.Workspace(vuln_app, []).search_code("hashlib", limit=1)["results"]
    assert len(hits) == 1 and hits[0]["path"] == "auth.py"


def _tool_call(name, args, i="c1"):
    return {"content": None, "tool_calls": [{"id": i, "name": name, "arguments": json.dumps(args)}]}


async def test_chat_uses_tools(vuln_app, cfg):
    f = _finding(vuln_app)
    ws = chat.Workspace(vuln_app, [f])
    fake = FakeLLMCompletion([_tool_call("get_finding", {"id": f["id"]}),
                              _tool_call("read_file", {"path": "db.py", "start_line": 10, "end_line": 15}, "c2"),
                              f"The finding `{f['id']}` is real."])
    reply, ids = await chat.chat(llm.LLM(cfg, fake), ws, "is the SQL one real?", [], True)
    assert "is real" in reply and ids == [f["id"]]
    assert fake.calls[0]["tools"] and len(fake.calls) == 3
    tool_msgs = [m for m in fake.calls[2]["messages"] if m["role"] == "tool"]
    assert "cur.execute" in tool_msgs[1]["content"]


async def test_chat_stops_after_8_steps(vuln_app, cfg):
    ws = chat.Workspace(vuln_app, [])
    fake = FakeLLMCompletion(fn=lambda m, t: _tool_call("search_code", {"query": "x"}) if t else
                             {"content": "best effort answer", "tool_calls": []})
    reply, _ = await chat.chat(llm.LLM(cfg, fake), ws, "find everything", [], True)
    assert reply == "best effort answer" and len(fake.calls) == 9 and fake.calls[-1]["tools"] is None


async def test_chat_without_tool_calling_includes_named_file(vuln_app, cfg):
    fake = FakeLLMCompletion(["Here is what auth.py does."])
    hist = [{"role": "user", "text": "hi"}, {"role": "assistant", "text": "hello"}]
    await chat.chat(llm.LLM(cfg, fake), chat.Workspace(vuln_app, []), "what does auth.py do?", hist, False)
    call = fake.calls[0]
    assert call["tools"] is None
    assert "hashlib.md5" in call["messages"][0]["content"]
    assert [m["role"] for m in call["messages"]] == ["system", "user", "assistant", "user"]


def test_parse_review_tolerates_small_model_output():
    raw = """{"verdict": "Likely Real", "explanation": "MD5 is weak.", "fix_recommendation": "Use bcrypt.",
     "suggested_patch": {"__original_line_6": "md5(x)", "__replacement_code_6": 'bcrypt.hashpw(x, salt)'}}"""
    r = llm.parse_review(raw)
    assert r == {"verdict": "likely_real", "explanation": "MD5 is weak.", "fix_recommendation": "Use bcrypt.",
                 "suggested_patch": "bcrypt.hashpw(x, salt)"}
    assert llm.parse_review('{"verdict": "unsure", "explanation": "x", "fix_recommendation": "y", '
                            '"suggested_patch": null}')["suggested_patch"] is None
    assert llm.parse_review('{"verdict": "maybe", "explanation": "x", "fix_recommendation": "y"}') is None
    assert llm.parse_review("no json here") is None


async def test_chat_falls_back_to_no_tools_when_tool_call_fails(vuln_app, cfg):
    calls = []

    async def flaky(messages, tools=None):
        calls.append(tools)
        if tools:
            raise llm.LLMError("The LLM returned an error (bad tool output)")
        return {"content": "Hello!", "tool_calls": []}

    reply, _ = await chat.chat(llm.LLM(cfg, flaky), chat.Workspace(vuln_app, []), "hi", [], True)
    assert reply == "Hello!" and calls[0] is not None and calls[1] is None


async def test_llm_errors_are_mapped(cfg, monkeypatch):
    import litellm

    async def boom(**kw):
        raise litellm.BadRequestError(message='{"code":500,"message":"The model produced output that does not '
                                      'match the expected peg-native format"}', model="m", llm_provider="openai")

    monkeypatch.setattr(litellm, "acompletion", boom)
    with pytest.raises(llm.LLMError, match="peg-native format"):
        await llm.LLM(cfg).complete([{"role": "user", "content": "hi"}])


def test_parse_review_odd_patch_shapes():
    base = '{"verdict": "likely_real", "explanation": "x", "fix_recommendation": "y", "suggested_patch": %s}'
    assert llm.parse_review(base % "{'a = 1', 'b = 2'}")["suggested_patch"] in ("a = 1\nb = 2", "b = 2\na = 1")
    assert llm.parse_review(base % '["a = 1", "b = 2"]')["suggested_patch"] == "a = 1\nb = 2"
    assert llm.parse_review(base % "{'old': {1, 2}}")["suggested_patch"]  # set inside a dict: no crash
    assert llm.parse_review(base % "42")["suggested_patch"] == "42"
