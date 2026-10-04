import httpx

from harness import auth
from mcp_client import call, connect


def test_hash_and_lookup(tmp_path):
    f = tmp_path / "t.json"
    tok = auth.add_user(f, "u1", "User One")
    assert auth.lookup(f, tok) == "u1"
    assert auth.lookup(f, tok + "x") is None
    assert auth.lookup(f, "") is None
    assert tok not in f.read_text()
    assert auth.hash_token(tok) in f.read_text()


def test_new_token_replaces_old(tmp_path):
    f = tmp_path / "t.json"
    old = auth.add_user(f, "u1", "U")
    new = auth.add_user(f, "u1", "U")
    assert auth.lookup(f, old) is None and auth.lookup(f, new) == "u1"


def test_bearer_parsing():
    assert auth.bearer({"authorization": "Bearer abc"}) == "abc"
    assert auth.bearer({"authorization": "Basic abc"}) is None
    assert auth.bearer({}) is None


def test_health(server):
    assert httpx.get(server + "/health").json() == {"status": "ok"}


def test_mcp_requires_token(server):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert httpx.post(server + "/mcp", json=body).status_code == 401
    r = httpx.post(server + "/mcp", json=body, headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
