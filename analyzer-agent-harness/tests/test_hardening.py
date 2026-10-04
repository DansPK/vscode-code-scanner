import io
import logging

from conftest import needs_scanners
from flow import sync_upload_scan
from harness import logs
from mcp_client import call, connect
from test_scanners import SECRETS


def test_log_lines_carry_ids():
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.addFilter(logs.ContextFilter())
    h.setFormatter(logging.Formatter("%(name)s%(ctx)s: %(message)s"))
    log = logging.getLogger("t")
    log.addHandler(h)
    log.setLevel(logging.INFO)
    try:
        token = logs.context.set({})
        logs.bind(session="s1", scan="x9")
        log.info("hello")
        logs.context.reset(token)
    finally:
        log.removeHandler(h)
    assert buf.getvalue().strip() == "t session=s1 scan=x9: hello"


@needs_scanners
async def test_no_secrets_or_tokens_in_logs(harness_server, tokens, vuln_app, caplog):
    caplog.set_level(logging.DEBUG)
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        _, summary, _ = await sync_upload_scan(c, sid, vuln_app)
        assert summary["status"] == "done"
        await call(c, "chat", {"session_id": sid, "message": "what about config.py?"})
    # Server-side records only (the test's own HTTP client logs the URLs it calls).
    text = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith(("httpx", "httpcore")))
    for s in SECRETS + [tokens["alice"], harness_server.cfg.signing_secret]:
        assert s not in text
    assert "sig=" not in text
    # Nothing the LLM saw contains the planted secrets either
    assert not any(s in repr(harness_server.llm.calls) for s in SECRETS)


async def test_unreachable_llm_in_chat_is_a_clear_error(harness_server, tokens):
    from harness.llm import LLMUnreachable

    async def down(messages, tools=None):
        raise LLMUnreachable("The LLM cannot be reached at http://llm")

    harness_server.service.llm._completion = down
    async with connect(harness_server.url, tokens["alice"]) as c:
        sid = (await call(c, "create_session", {}))["session_id"]
        try:
            await call(c, "chat", {"session_id": sid, "message": "hi"})
        except RuntimeError as e:
            assert "cannot be reached" in str(e)
        else:
            raise AssertionError("expected an error")


def test_signatures_are_redacted():
    f = logs.RedactingFormatter("%(message)s")
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "PUT /uploads/x?expires=1&sig=abc123 201", (), None)
    assert f.format(rec) == "PUT /uploads/x?expires=1&sig=*** 201"
