import assert from "node:assert/strict";
import { randomUUID } from "crypto";
import * as http from "http";
import { test } from "node:test";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { HarnessClient } from "../../src/client";

/** A server with MCP sessions, like the harness: after a restart it answers old session ids with 404. */
function statefulServer() {
  let sessions = new Map<string, StreamableHTTPServerTransport>();
  let calls = 0;
  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
    const sid = req.headers["mcp-session-id"] as string | undefined;
    let t = sid ? sessions.get(sid) : undefined;
    if (sid && !t) {
      res.writeHead(404, { "content-type": "application/json" })
        .end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Session not found" } }));
      return;
    }
    if (!t) {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(), onsessioninitialized: (id) => { sessions.set(id, transport); },
      });
      const mcp = new McpServer({ name: "s", version: "1" });
      mcp.tool("list_sessions", {}, async () => {
        calls++;
        return { content: [{ type: "text" as const, text: JSON.stringify({ sessions: [] }) }] };
      });
      await mcp.connect(transport);
      t = transport;
    }
    await t.handleRequest(req, res, body);
  });
  return { server, restart: () => { sessions = new Map(); }, calls: () => calls };
}

test("after the harness restarts, the next call connects again and is sent once", async () => {
  const s = statefulServer();
  await new Promise<void>((r) => s.server.listen(0, "127.0.0.1", r));
  const port = (s.server.address() as { port: number }).port;
  const c = new HarnessClient(`http://127.0.0.1:${port}`, "t");
  try {
    await c.connect();
    assert.deepEqual(await c.listSessions(), { sessions: [] });
    s.restart();
    assert.deepEqual(await c.listSessions(), { sessions: [] }); // no error for the user
    assert.equal(s.calls(), 2); // refused, not run, so the retry did not run it twice
  } finally {
    await c.close();
    s.server.closeAllConnections();
    s.server.close();
  }
});
