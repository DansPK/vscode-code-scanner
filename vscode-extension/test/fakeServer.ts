// A fake harness for tests: the contract's MCP tools with in-memory state,
// the presigned upload URL (with hash check), and progress notifications in watch_scan.
// Run directly to use it by hand: `npm run fake-server` (token "test-token", port 7357).

import { createHash, randomUUID } from "crypto";
import * as http from "http";
import * as https from "https";
import { AddressInfo } from "net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { route } from "../src/routing";
import type { ChatAction, Finding, ManifestEntry, ScanSummary } from "../src/shared/contract";

export interface FakeOptions {
  token?: string;
  port?: number;
  /** Milliseconds between scan progress steps. */
  stepMs?: number;
  /** Findings to return; `path` values should exist in the test workspace. */
  findings?: Partial<Finding>[];
  /** Serve HTTPS with this PEM certificate and key. */
  tls?: { cert: string; key: string };
}

interface Session {
  id: string; owner: string; name: string; target_type: "workspace" | "github"; repo_url: string | null;
  created_at: string; manifest: Map<string, ManifestEntry>; pending: ManifestEntry[] | null;
  messages: { role: "user" | "assistant"; text: string; finding_ids: string[] }[];
}

interface Upload { id: string; session: string; size: number; sha256: string; expires: number; used: boolean;
  data?: Buffer }

export class FakeHarness {
  token: string;
  url = "";
  sessions = new Map<string, Session>();
  uploads = new Map<string, Upload>();
  scans = new Map<string, ScanSummary>();
  calls: { name: string; args: any }[] = [];
  /** When set, the next watch_scan drops its connection after the first progress notification. */
  dropNextWatch = false;
  /** When set, the next upload is answered with this status. */
  forceUploadStatus: number | null = null;
  /** When set, chat fails as if the LLM were down. */
  llmDown = false;
  private server?: http.Server | https.Server;
  private timers = new Set<NodeJS.Timeout>();

  constructor(private opts: FakeOptions = {}) {
    this.token = opts.token ?? "test-token";
  }

  async start(): Promise<string> {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => this.handle(req, res).catch((e) => {
      if (!res.headersSent) res.writeHead(500);
      res.end(String(e));
    });
    this.server = this.opts.tls ? https.createServer(this.opts.tls, handler) : http.createServer(handler);
    await new Promise<void>((r) => this.server!.listen(this.opts.port ?? 0, "127.0.0.1", r));
    this.url = `${this.opts.tls ? "https" : "http"}://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
    return this.url;
  }

  async stop() {
    for (const t of this.timers) clearInterval(t);
    this.server?.closeAllConnections();
    await new Promise((r) => this.server?.close(r));
  }

  lastUploadArchive(): Buffer | undefined {
    return [...this.uploads.values()].filter((u) => u.data).pop()?.data;
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url ?? "/", this.url);
    if (url.pathname.startsWith("/uploads/") && req.method === "PUT") {
      await this.receiveUpload(req, res, url);
      return;
    }
    if (url.pathname !== "/mcp") {
      res.writeHead(404).end();
      return;
    }
    if (req.headers.authorization !== `Bearer ${this.token}`) {
      res.writeHead(401, { "content-type": "application/json" }).end('{"error":"unauthorized"}');
      return;
    }
    const body = req.method === "POST" ? JSON.parse((await readBody(req)).toString() || "null") : undefined;
    const server = new Server({ name: "fake-harness", version: "1.0.0" }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: TOOL_NAMES.map((name) => ({ name, inputSchema: { type: "object" as const } })),
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const { name, arguments: args = {} } = request.params;
      this.calls.push({ name, args });
      try {
        const result = await this.tool(name, args as any, extra, request.params._meta?.progressToken, res);
        return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result };
      } catch (e) {
        return { isError: true, content: [{ type: "text", text: (e as Error).message }] };
      }
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  }

  private session(id: string) {
    const s = this.sessions.get(id);
    if (!s) throw new Error("session not found");
    return s;
  }

  private async tool(name: string, a: any, extra: any, progressToken: string | number | undefined,
                     res: http.ServerResponse): Promise<any> {
    switch (name) {
      case "create_session": {
        const id = randomUUID().replace(/-/g, "").slice(0, 24);
        if (a.target_type === "github" && !/^https:\/\/github\.com\/[\w-]+\/[\w.-]+?(\.git)?\/?$/.test(a.repo_url ?? "")) {
          throw new Error("only https://github.com/<owner>/<repo> links are supported");
        }
        this.sessions.set(id, {
          id, owner: "me", name: a.name ?? (a.target_type === "github" ? a.repo_url.split("github.com/")[1] : "Workspace scan"),
          target_type: a.target_type ?? "workspace", repo_url: a.repo_url ?? null,
          created_at: new Date().toISOString(), manifest: new Map(), pending: null, messages: [],
        });
        return { session_id: id };
      }
      case "list_sessions":
        return { sessions: [...this.sessions.values()].map((s) => this.sessionFields(s)) };
      case "get_session": {
        const s = this.session(a.session_id);
        const latest = this.latestScan(s.id);
        return { session: this.sessionFields(s), messages: s.messages.slice(-(a.message_limit ?? 50)),
                 latest_scan_id: latest?.scan_id ?? null, file_count: s.manifest.size };
      }
      case "rename_session":
        this.session(a.session_id).name = a.name;
        return { ok: true };
      case "delete_session":
        this.session(a.session_id);
        this.sessions.delete(a.session_id);
        return { ok: true };
      case "sync_files": {
        const s = this.session(a.session_id);
        const m: ManifestEntry[] = a.manifest;
        const need = m.filter((e) => s.manifest.get(e.path)?.sha256 !== e.sha256).map((e) => e.path);
        const seen = new Set(m.map((e) => e.path));
        const del = [...s.manifest.keys()].filter((p) => !seen.has(p)).sort();
        s.pending = m;
        return { need, delete: del, unchanged_count: m.length - need.length };
      }
      case "request_upload": {
        this.session(a.session_id);
        const id = randomUUID();
        const expires = Date.now() + 600_000;
        this.uploads.set(id, { id, session: a.session_id, size: a.size_bytes, sha256: a.sha256, expires, used: false });
        return { upload_id: id, upload_url: `${this.url}/uploads/${id}?sig=fake`,
                 expires_at: new Date(expires).toISOString() };
      }
      case "start_scan": {
        const s = this.session(a.session_id);
        if ([...this.scans.values()].some((x) => x.session_id === s.id && (x.status === "running" || x.status === "queued"))) {
          throw new Error("a scan is already running for this session");
        }
        if (s.target_type === "workspace") {
          if (s.pending) {
            for (const e of s.pending) s.manifest.set(e.path, e);
            for (const p of [...s.manifest.keys()]) if (!s.pending.some((e) => e.path === p)) s.manifest.delete(p);
            s.pending = null;
          }
          if (a.upload_id && !this.uploads.get(a.upload_id)?.data) throw new Error("upload not found");
        }
        return { scan_id: this.runScan(s) };
      }
      case "watch_scan": {
        const scan = this.scans.get(a.scan_id);
        if (!scan) throw new Error("scan not found");
        let first = true;
        while (scan.status === "running" || scan.status === "queued") {
          if (progressToken !== undefined) {
            await extra.sendNotification({ method: "notifications/progress",
              params: { progressToken, progress: scan.percent, total: 100, message: `Scanning: ${scan.percent}%` } });
          }
          if (first && this.dropNextWatch) {
            this.dropNextWatch = false;
            await sleep(20);
            res.destroy();
            await sleep(10_000);
          }
          first = false;
          await sleep(this.step / 2);
        }
        return scan;
      }
      case "get_scan_status": {
        const scan = this.scans.get(a.scan_id);
        if (!scan) throw new Error("scan not found");
        return scan;
      }
      case "cancel_scan": {
        const scan = this.scans.get(a.scan_id);
        if (!scan) throw new Error("scan not found");
        scan.status = "cancelled";
        scan.finished_at = new Date().toISOString();
        return { ok: true };
      }
      case "get_findings": {
        const s = this.session(a.session_id);
        const scan = a.scan_id ? this.scans.get(a.scan_id) : this.latestScan(s.id, true);
        let all = scan ? this.findingsFor(s) : [];
        if (scan && scan.status === "running") {
          // While a scan runs, findings come in gradually and have not been reviewed yet.
          all = all.slice(0, Math.ceil((all.length * scan.percent) / 100))
            .map((f) => ({ ...f, explanation: "", fix_recommendation: "", verdict: "unsure" as const }));
        }
        const off = a.offset ?? 0;
        const lim = a.limit ?? 200;
        return { findings: all.slice(off, off + lim), total: all.length };
      }
      case "chat": {
        const s = this.session(a.session_id);
        if (this.llmDown) throw new Error("The LLM cannot be reached at http://llm.invalid");
        const { reply, action } = this.agent(s, a.message);
        s.messages.push({ role: "user", text: a.message, finding_ids: [] },
                        { role: "assistant", text: reply, finding_ids: [] });
        return { reply, finding_ids: [], action };
      }
    }
    throw new Error(`unknown tool ${name}`);
  }

  get stepMs() {
    return this.opts.stepMs ?? 50;
  }

  set stepMs(ms: number) {
    this.opts.stepMs = ms;
  }

  /** A stand-in for the harness's agent: decides with simple rules what the message wants. */
  private agent(s: Session, text: string): { reply: string; action: ChatAction | null } {
    const base = { full: false, paths: [] as string[], url: null as string | null, confirm: false };
    const running = [...this.scans.values()].some((x) => x.session_id === s.id && x.status === "running");
    if (/^\s*(stop|cancel)\b/i.test(text)) {
      return running ? { reply: "Stopping the scan.", action: { ...base, type: "cancel" } }
        : { reply: "No scan is running right now.", action: null };
    }
    const r = route(text);
    if (r.kind === "github") return { reply: `Scanning ${r.url}.`, action: { ...base, type: "scan_github", url: r.url } };
    if (/\bsafe\?/i.test(text)) {
      return { reply: "Do you want me to scan the workspace?", action: { ...base, type: "scan", confirm: true } };
    }
    if (r.kind === "scan" || r.kind === "rescan" || /\bscan\b/i.test(text)) {
      const only = text.match(/\bonly (?:the )?([\w./-]+?)(?: folder)?\s*$/i);
      const full = /from scratch|full scan/i.test(text);
      return { reply: "Starting a scan.", action: { ...base, type: "scan", full, paths: only ? [only[1]] : [] } };
    }
    const reply = `You said: **${text}**\n\n\`\`\`js\nconsole.log("hi")\n\`\`\``;
    return { reply, action: null };
  }

  private get step() {
    return this.stepMs;
  }

  private runScan(s: Session) {
    const id = randomUUID().replace(/-/g, "").slice(0, 24);
    const scan: ScanSummary = { scan_id: id, session_id: s.id, status: "running", stage: "semgrep", percent: 0,
      counts: {}, error: null, started_at: new Date().toISOString(), finished_at: null };
    this.scans.set(id, scan);
    const t = setInterval(() => {
      if (scan.status !== "running") {
        clearInterval(t);
        return;
      }
      scan.percent = Math.min(scan.percent + 25, 100);
      if (scan.percent === 100) {
        scan.status = "done";
        scan.stage = "finished";
        scan.error = "sonarqube: SonarQube cannot be reached";
        scan.finished_at = new Date().toISOString();
        const counts: Record<string, number> = {};
        for (const f of this.findingsFor(s)) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
        scan.counts = counts;
        clearInterval(t);
      }
    }, this.step);
    this.timers.add(t);
    return id;
  }

  private findingsFor(s: Session): Finding[] {
    return (this.opts.findings ?? []).map((o, i) => {
      const f: Finding = {
        id: `f${i}`, tools: ["semgrep"], rule_id: "rule", title: `Finding ${i}`, severity: "high", cwe: null,
        path: "app.js", start_line: 1, end_line: 1, start_col: null, end_col: null, file_sha256: "", message: "m",
        snippet: "", verdict: "likely_real", explanation: "Explanation. More text.",
        fix_recommendation: "Fix it this way. Then test.", suggested_patch: null, status: "new", web_url: null, ...o,
      };
      f.file_sha256 = s.manifest.get(f.path)?.sha256 ?? "";
      if (s.target_type === "github") f.web_url = `${s.repo_url}/blob/abc/${f.path}#L${f.start_line}-L${f.end_line}`;
      return f;
    });
  }

  private latestScan(sessionId: string, doneOnly = false) {
    return [...this.scans.values()].filter((x) => x.session_id === sessionId && (!doneOnly || x.status === "done")).pop();
  }

  private sessionFields(s: Session) {
    const last = this.latestScan(s.id);
    return { session_id: s.id, name: s.name, target_type: s.target_type, repo_url: s.repo_url,
             created_at: s.created_at, last_scan_at: last?.started_at ?? null, last_scan_status: last?.status ?? null };
  }

  private async receiveUpload(req: http.IncomingMessage, res: http.ServerResponse, url: URL): Promise<void> {
    const id = url.pathname.split("/").pop()!;
    const u = this.uploads.get(id);
    const data = await readBody(req);
    const send = (code: number, msg: string) => res.writeHead(code, { "content-type": "application/json" })
      .end(JSON.stringify({ error: msg }));
    if (this.forceUploadStatus) {
      const code = this.forceUploadStatus;
      this.forceUploadStatus = null;
      send(code, "forced");
      return;
    }
    if (!u || url.searchParams.get("sig") !== "fake" || Date.now() > u.expires) {
      send(403, "bad signature");
      return;
    }
    if (u.used) {
      send(409, "already used");
      return;
    }
    u.used = true;
    const sha = createHash("sha256").update(data).digest("hex");
    if (data.length !== u.size || sha !== u.sha256) {
      send(400, "size or hash mismatch");
      return;
    }
    u.data = data;
    res.writeHead(201, { "content-type": "application/json" }).end('{"ok":true}');
  }
}

const TOOL_NAMES = ["create_session", "list_sessions", "get_session", "rename_session", "delete_session",
  "sync_files", "request_upload", "start_scan", "watch_scan", "get_scan_status", "cancel_scan", "get_findings", "chat"];

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

if (require.main === module) {
  const h = new FakeHarness({ port: Number(process.env.PORT ?? 7357), stepMs: 1000,
    findings: [{ path: "src/index.js", title: "SQL injection", severity: "critical" }] });
  h.start().then((url) => console.log(`Fake harness on ${url} (token: ${h.token})`));
}
