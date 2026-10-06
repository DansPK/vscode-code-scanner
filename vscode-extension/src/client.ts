// MCP client for the harness: connects with the bearer token and calls the contract's tools.

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { FetchFn, tlsErrorCode } from "./http";
import type { ChatReply, FindingsPage, FixResult, ManifestEntry, ScanSummary, SessionDetail, SessionInfo, SyncResult,
  UploadTicket } from "./shared/contract";

export const TOKEN_REJECTED = "Token rejected. Run Vuln Scanner: Set Token.";
const CALL_TIMEOUT_MS = 120_000;
const WATCH_IDLE_TIMEOUT_MS = 60_000; // reset by every progress notification (the harness sends one at least every 15 s)
const WATCH_TOTAL_TIMEOUT_MS = 2 * 60 * 60 * 1000;

export class TokenRejectedError extends Error {
  constructor() {
    super(TOKEN_REJECTED);
  }
}

export class ServerUnreachableError extends Error {}

/** An error the harness returned for a tool call; its message is meant for the user. */
export class ToolCallError extends Error {}

export function mapError(e: unknown, serverUrl: string): Error {
  if (e instanceof TokenRejectedError || e instanceof ToolCallError || e instanceof ServerUnreachableError) return e;
  const tlsCode = tlsErrorCode(e);
  if (tlsCode) {
    return new ServerUnreachableError(`The server's HTTPS certificate is not trusted (${tlsCode}). `
      + "For a self-signed certificate, set vulnScanner.caCertificate to its .pem file.");
  }
  const err = e as Error & { code?: number };
  if ((e instanceof StreamableHTTPError && e.code === 401) || /\b401\b|unauthori[sz]ed/i.test(err?.message ?? "")) {
    return new TokenRejectedError();
  }
  if (/fetch failed|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|socket hang up|terminated|network/i
    .test(`${err?.message} ${(err as any)?.cause?.code ?? ""} ${(err as any)?.cause?.message ?? ""}`)) {
    return new ServerUnreachableError(`The scanner server cannot be reached at ${serverUrl}.`);
  }
  return err instanceof Error ? err : new Error(String(e));
}

export class HarnessClient {
  private client?: Client;

  constructor(readonly serverUrl: string, private readonly token: string, readonly fetchFn: FetchFn = fetch) {}

  get connected() {
    return this.client !== undefined;
  }

  async connect(): Promise<void> {
    const client = new Client({ name: "vuln-scanner-vscode", version: "0.1.0" });
    const transport = new StreamableHTTPClientTransport(new URL(this.serverUrl.replace(/\/+$/, "") + "/mcp"), {
      requestInit: { headers: { Authorization: `Bearer ${this.token}` } },
      fetch: this.fetchFn,
    });
    try {
      await client.connect(transport);
    } catch (e) {
      await client.close().catch(() => undefined);
      throw mapError(e, this.serverUrl);
    }
    this.client = client;
  }

  async close() {
    const c = this.client;
    this.client = undefined;
    await c?.close().catch(() => undefined);
  }

  async call<T>(name: string, args: Record<string, unknown> = {}, opts: {
    onprogress?: (p: { progress: number; total?: number; message?: string }) => void;
    long?: boolean; signal?: AbortSignal;
  } = {}): Promise<T> {
    if (!this.client) await this.connect();
    const send = () => this.client!.callTool({ name, arguments: args }, undefined, {
      onprogress: opts.onprogress, signal: opts.signal,
      timeout: opts.long ? WATCH_IDLE_TIMEOUT_MS : CALL_TIMEOUT_MS,
      resetTimeoutOnProgress: opts.long,
      maxTotalTimeout: opts.long ? WATCH_TOTAL_TIMEOUT_MS : undefined,
    });
    let result;
    try {
      try {
        result = await send();
      } catch (e) {
        // The harness restarted and forgot our MCP session. It refused the call without running it,
        // so connecting again and sending it once more is safe.
        if (!(e instanceof StreamableHTTPError && e.code === 404)) throw e;
        await this.close();
        await this.connect();
        result = await send();
      }
    } catch (e) {
      if (e instanceof McpError && e.code === ErrorCode.RequestTimeout) {
        // No answer: the connection may be dead (for example the harness restarted mid-call). The call may
        // have run, so it is not repeated; the next call connects again.
        await this.close();
        throw new Error("The scanner server did not answer in time. It may have restarted; try again.");
      }
      const mapped = mapError(e, this.serverUrl);
      if (mapped instanceof ServerUnreachableError || mapped instanceof TokenRejectedError) await this.close();
      throw mapped;
    }
    const text = (result.content as { type: string; text?: string }[] | undefined)?.find((c) => c.type === "text")?.text ?? "";
    if (result.isError) throw new ToolCallError(text || `${name} failed`);
    if (result.structuredContent) {
      const sc = result.structuredContent as Record<string, unknown>;
      return (Object.keys(sc).length === 1 && "result" in sc ? sc.result : sc) as T;
    }
    return JSON.parse(text) as T;
  }

  // --- the contract's tools ---

  createSession(target_type: "workspace" | "github", repo_url?: string, name?: string) {
    return this.call<{ session_id: string }>("create_session", { target_type, repo_url, name });
  }
  listSessions() {
    return this.call<{ sessions: SessionInfo[] }>("list_sessions");
  }
  getSession(session_id: string, message_limit = 50) {
    return this.call<SessionDetail>("get_session", { session_id, message_limit });
  }
  renameSession(session_id: string, name: string) {
    return this.call<{ ok: boolean }>("rename_session", { session_id, name });
  }
  deleteSession(session_id: string) {
    return this.call<{ ok: boolean }>("delete_session", { session_id });
  }
  syncFiles(session_id: string, manifest: ManifestEntry[]) {
    return this.call<SyncResult>("sync_files", { session_id, manifest });
  }
  requestUpload(session_id: string, size_bytes: number, sha256: string) {
    return this.call<UploadTicket>("request_upload", { session_id, size_bytes, sha256 });
  }
  startScan(session_id: string,
            opts: { upload_id?: string; deleted_paths?: string[]; full?: boolean; paths?: string[] } = {}) {
    return this.call<{ scan_id: string }>("start_scan", { session_id, ...opts });
  }
  watchScan(scan_id: string, onProgress: (percent: number, message: string) => void, signal?: AbortSignal) {
    return this.call<ScanSummary>("watch_scan", { scan_id }, {
      long: true, signal, onprogress: (p) => onProgress(Math.round(p.progress), p.message ?? ""),
    });
  }
  getScanStatus(scan_id: string) {
    return this.call<ScanSummary>("get_scan_status", { scan_id });
  }
  cancelScan(scan_id: string) {
    return this.call<{ ok: boolean }>("cancel_scan", { scan_id });
  }
  getFindings(session_id: string, opts: { scan_id?: string; limit?: number; offset?: number } = {}) {
    return this.call<FindingsPage>("get_findings", { session_id, ...opts });
  }
  chat(session_id: string, message: string) {
    return this.call<ChatReply>("chat", { session_id, message });
  }
  summarizeFindings(session_id: string) {
    return this.call<{ summary: string; finding_ids: string[] }>("summarize_findings", { session_id });
  }
  fixFindings(session_id: string, finding_ids: string[], onProgress: (percent: number, message: string) => void,
              signal?: AbortSignal) {
    return this.call<FixResult>("fix_findings", { session_id, finding_ids }, {
      long: true, signal, onprogress: (p) => onProgress(Math.round(p.progress), p.message ?? ""),
    });
  }
}
