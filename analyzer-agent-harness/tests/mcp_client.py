"""Small helper to talk to the harness as an MCP client in tests."""

import json
from contextlib import asynccontextmanager

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


@asynccontextmanager
async def connect(base_url, token, verify=True):
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60, verify=verify)
    async with http, Client(streamable_http_client(base_url + "/mcp", http_client=http)) as c:
        yield c


async def call(client, name, args=None, **kw):
    """Call a tool and return its JSON result. Raises on a tool error."""
    r = await client.call_tool(name, args or {}, **kw)
    text = r.content[0].text if r.content else ""
    if r.is_error:
        raise RuntimeError(text)
    if r.structured_content is not None:
        sc = r.structured_content
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(text)
