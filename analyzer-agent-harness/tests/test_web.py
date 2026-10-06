import json

import httpx
import pytest

from fakes import FakeLLMCompletion
from harness import chat, web
from harness.llm import LLM


REAL_CLIENT = httpx.AsyncClient


def _mock(monkeypatch, handler):
    """Make web's httpx clients answer from `handler` instead of the network."""
    monkeypatch.setattr(web.httpx, "AsyncClient",
                        lambda **kw: REAL_CLIENT(transport=httpx.MockTransport(handler), **kw))


def test_queries_are_short_and_never_carry_a_secret():
    assert web.check_query("  CWE-89   sqlite3 ") == "CWE-89 sqlite3"
    assert len(web.check_query("x" * 500)) == web.MAX_QUERY_CHARS
    for bad in ["", "   ", "is sk_l**** a stripe key"]:
        with pytest.raises(web.WebError):
            web.check_query(bad)


async def test_search_reads_searxng_json(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"results": [
            {"title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html", "content": "SQL  injection"},
            {"title": "Other", "url": "https://example.org", "content": "x"}]})
    _mock(monkeypatch, handler)
    r = await web.call("http://searxng:8080", "web_search", {"query": "sql injection", "limit": 1})
    assert r == {"results": [{"title": "CWE-89", "url": "https://cwe.mitre.org/data/definitions/89.html",
                              "snippet": "SQL injection"}]}
    assert seen[0].url.params["format"] == "json" and seen[0].url.path == "/search"

    _mock(monkeypatch, lambda request: httpx.Response(500))
    assert "failed" in (await web.call("http://searxng:8080", "web_search", {"query": "x"}))["error"]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost:8080/", "http://10.1.2.3/", "http://192.168.1.50:1234/v1",
    "http://172.17.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
    "file:///etc/passwd", "ftp://example.org/", "http://user:pw@93.184.216.34/"])
async def test_private_and_odd_addresses_are_refused(url):
    with pytest.raises(web.WebError):
        await web.check_url(url)


async def test_fetch_gives_readable_text_and_checks_every_redirect(monkeypatch):
    page = ("<html><head><title> SQL  Injection </title><style>p{}</style></head><body><nav>menu</nav>"
            "<h1>Prevention</h1><p>Use bound&nbsp;parameters.</p><script>evil()</script></body></html>")

    def handler(request):
        if request.url.path == "/go":
            return httpx.Response(302, headers={"location": "/page"})
        if request.url.path == "/inside":
            return httpx.Response(302, headers={"location": "http://10.0.0.5/admin"})
        return httpx.Response(200, text=page, headers={"content-type": "text/html; charset=utf-8"})
    _mock(monkeypatch, handler)
    r = await web.call(None, "fetch_url", {"url": "http://93.184.216.34/go"})  # an IP literal: no DNS needed
    assert r["title"] == "SQL Injection" and r["url"].endswith("/page")
    assert "Use bound\xa0parameters." in r["text"] and "Prevention" in r["text"]
    assert "evil" not in r["text"] and "menu" not in r["text"]
    r = await web.call(None, "fetch_url", {"url": "http://93.184.216.34/inside"})  # redirect into the LAN
    assert "not public" in r["error"]


async def test_chat_agent_gets_web_tools_only_when_configured(monkeypatch, tmp_path):
    async def fake_search(base, query, limit=5):
        return [{"title": "CWE-89", "url": "https://cwe.mitre.org", "snippet": "Use parameters."}]
    monkeypatch.setattr(web, "search", fake_search)

    def fn(messages, tools):
        if messages[-1]["role"] == "tool":
            return {"content": "Per CWE-89, use parameters.", "tool_calls": []}
        return {"content": "", "tool_calls": [{"id": "1", "name": "web_search",
                                               "arguments": json.dumps({"query": "CWE-89 fix"})}]}
    fake = FakeLLMCompletion(fn=fn)
    ws = chat.Workspace(tmp_path, [])
    text, _ = await chat.chat(LLM(cfg_stub(), fake), ws, "how do I fix sql injection?", [], True, "http://searxng:8080")
    assert text == "Per CWE-89, use parameters."
    assert "web_search" in [t["function"]["name"] for t in fake.calls[0]["tools"]]
    assert "never put code" in fake.calls[0]["messages"][0]["content"]
    assert "Use parameters." in fake.calls[1]["messages"][-1]["content"]

    fake = FakeLLMCompletion(fn=lambda m, t: {"content": "ok", "tool_calls": []})
    await chat.chat(LLM(cfg_stub(), fake), ws, "hi", [], True, None)
    assert "web_search" not in [t["function"]["name"] for t in fake.calls[0]["tools"]]


def test_fix_agent_transcript_lines_for_web_tools():
    from harness.agent import _describe, _outcome
    assert _describe("web_search", {"query": "CWE-89 python"}) == "Web search 'CWE-89 python'"
    assert _describe("fetch_url", {"url": "https://cwe.mitre.org/data/89.html"}) == "Fetch cwe.mitre.org"
    assert _outcome("web_search", {}, json.dumps({"results": [{"url": "a"}, {"url": "b"}]})) == "2 results"
    assert _outcome("fetch_url", {}, json.dumps({"title": "CWE-89", "text": "x"})) == "CWE-89"


def cfg_stub():
    from types import SimpleNamespace
    return SimpleNamespace(llm_context_tokens=32000)
