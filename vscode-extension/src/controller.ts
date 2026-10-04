// Ties VS Code to the harness: connection, sessions, chat, scans, findings and editor markers.

import * as path from "path";
import * as vscode from "vscode";
import { formatBytes } from "./archive";
import { HarnessClient, ServerUnreachableError, TOKEN_REJECTED, TokenRejectedError, ToolCallError } from "./client";
import { diagnosticLevel, diagnosticMessage, scanSummaryText, sortFindings, splitHidden } from "./findingsLogic";
import { makeFetch } from "./http";
import { log } from "./log";
import { route } from "./routing";
import { fetchAllFindings, prepareWorkspace, TooLargeError, watchToEnd } from "./scanFlow";
import type { ChatAction, ChatMessage, Finding, SessionInfo } from "./shared/contract";
import type { ConnectionStatus, FindingView, ToExtension, ToWebview } from "./shared/messages";
import { UploadError } from "./upload";
import { CancelledError, hashFile } from "./workspaceFiles";

export const TOKEN_KEY = "vulnScanner.token";
const LAST_SESSION_KEY = "vulnScanner.lastSession";
const SESSION_FOLDERS_KEY = "vulnScanner.sessionFolders";
const LIVE_REFRESH_MS = 1500;
const SUGGEST_RESCAN_AFTER_MS = 4000;

export interface ScanOptions {
  full?: boolean;
  paths?: string[];
}

/** The keyword rules, used only when the agent cannot be reached. */
function keywordAction(text: string): ChatAction | null {
  const r = route(text);
  const base = { full: false, paths: [], url: null, confirm: false };
  if (r.kind === "github") return { ...base, type: "scan_github", url: r.url };
  if (r.kind === "rescan" || r.kind === "scan") return { ...base, type: "scan" };
  if (/^\s*(stop|cancel|abort)\b/i.test(text)) return { ...base, type: "cancel" };
  return null;
}

export interface View {
  post(msg: ToWebview): void;
}

interface RunningScan {
  scanId: string;
  sessionId: string;
  abort: AbortController;
}

export class Controller implements vscode.Disposable {
  private client?: HarnessClient;
  private connection: ConnectionStatus = { state: "connecting" };
  private sessions: SessionInfo[] = [];
  private current: string | null = null;
  private scanning: RunningScan | null = null;
  private busy = false;
  private findings: Finding[] = [];
  private readonly diagnostics: vscode.DiagnosticCollection;
  private views: View[] = [];
  private connecting?: Promise<boolean>;

  constructor(private readonly ctx: vscode.ExtensionContext) {
    this.diagnostics = vscode.languages.createDiagnosticCollection("vulnScanner");
  }

  dispose() {
    clearTimeout(this.suggestTimer);
    this.diagnostics.dispose();
    this.scanning?.abort.abort();
    void this.client?.close();
  }

  attach(view: View): vscode.Disposable {
    this.views.push(view);
    return { dispose: () => { this.views = this.views.filter((v) => v !== view); } };
  }

  private post(msg: ToWebview) {
    for (const v of this.views) v.post(msg);
  }

  private postState() {
    this.post({ type: "state", connection: this.connection, sessions: this.sessions, current: this.current,
                scanning: this.scanning !== null, busy: this.busy });
  }

  private say(text: string, role: ChatMessage["role"] = "assistant") {
    this.post({ type: "message", message: { role, text, finding_ids: [] } });
  }

  private settings() {
    const c = vscode.workspace.getConfiguration("vulnScanner");
    return {
      serverUrl: (c.get<string>("serverUrl") ?? "").trim(),
      maxFileSizeKB: c.get<number>("maxFileSizeKB", 2048),
      maxUploadMB: c.get<number>("maxUploadMB", 200),
      extraExcludes: c.get<string[]>("extraExcludes", []),
      showLikelyFalsePositives: c.get<boolean>("showLikelyFalsePositives", false),
      caCertificate: (c.get<string>("caCertificate") ?? "").trim(),
    };
  }

  private lastSessionKey() {
    const folder = vscode.workspace.workspaceFolders?.[0]?.uri.toString() ?? "none";
    return `${LAST_SESSION_KEY}:${folder}`;
  }

  // --- connection ---

  /** Connect (or reconnect) with the current settings and token, then restore the last session. */
  async connect(): Promise<void> {
    // `connecting` covers only the connection itself: loading sessions goes through ready(),
    // which waits on it, so it must not be part of the same promise.
    this.connecting = this.doConnect();
    if (!(await this.connecting)) return;
    try {
      await this.refreshSessions();
      const last = this.ctx.workspaceState.get<string>(this.lastSessionKey());
      if (last && this.sessions.some((s) => s.session_id === last)) await this.switchSession(last);
      else this.postState();
    } catch (e) {
      this.showError(e);
    }
  }

  /** A token pasted into the vulnScanner.token setting moves to secret storage, and the setting is cleared. */
  private async takeTokenFromSettings() {
    const c = vscode.workspace.getConfiguration("vulnScanner");
    const info = c.inspect<string>("token");
    const value = (info?.workspaceFolderValue || info?.workspaceValue || info?.globalValue || "").trim();
    if (!value) return;
    await this.ctx.secrets.store(TOKEN_KEY, value);
    const targets: [unknown, vscode.ConfigurationTarget][] = [
      [info?.globalValue, vscode.ConfigurationTarget.Global],
      [info?.workspaceValue, vscode.ConfigurationTarget.Workspace],
      [info?.workspaceFolderValue, vscode.ConfigurationTarget.WorkspaceFolder]];
    for (const [v, target] of targets) {
      if (v !== undefined) await c.update("token", undefined, target).then(undefined, () => undefined);
    }
    log.info("Token moved from settings to secret storage");
    void vscode.window.showInformationMessage(
      "Vuln Scanner: the token was saved in secure storage and removed from your settings file.");
  }

  private async doConnect(): Promise<boolean> {
    await this.client?.close();
    this.client = undefined;
    await this.takeTokenFromSettings();
    const { serverUrl, caCertificate } = this.settings();
    const token = await this.ctx.secrets.get(TOKEN_KEY);
    if (!serverUrl) {
      this.connection = { state: "disconnected", reason: "No server URL is set.",
                          action: { label: "Open Settings", command: "vulnScanner.openSettings" } };
      this.postState();
      return false;
    }
    if (!token) {
      this.connection = { state: "disconnected", reason: "No token is set.",
                          action: { label: "Set Token", command: "vulnScanner.setToken" } };
      this.postState();
      return false;
    }
    this.connection = { state: "connecting" };
    this.postState();
    let client: HarnessClient;
    try {
      client = new HarnessClient(serverUrl, token, makeFetch(caCertificate || undefined));
      await client.connect();
    } catch (e) {
      this.setDisconnected(e);
      return false;
    }
    this.client = client;
    this.connection = { state: "connected" };
    log.info(`Connected to ${serverUrl}`);
    return true;
  }

  private setDisconnected(e: unknown) {
    const err = e as Error;
    log.warn(`Connection problem: ${err.message}`);
    this.connection = e instanceof TokenRejectedError
      ? { state: "disconnected", reason: TOKEN_REJECTED, action: { label: "Set Token", command: "vulnScanner.setToken" } }
      : { state: "disconnected", reason: err.message || "Cannot connect.",
          action: { label: "Retry", command: "vulnScanner.reconnect" } };
    this.postState();
  }

  private async ready(): Promise<HarnessClient> {
    await this.connecting;
    if (!this.client) {
      if (this.connection.state === "disconnected") {
        throw new Error(this.connection.reason);
      }
      throw new Error("Not connected to the scanner server.");
    }
    return this.client;
  }

  async setToken(token: string) {
    await this.ctx.secrets.store(TOKEN_KEY, token);
    await this.connect();
  }

  async clearToken() {
    await this.ctx.secrets.delete(TOKEN_KEY);
    await this.connect();
  }

  // --- messages from the webview ---

  async handle(msg: ToExtension) {
    try {
      switch (msg.type) {
        case "ready":
          this.postState();
          if (this.current) await this.showSession(this.current);
          return;
        case "send": return await this.send(msg.text);
        case "cancel": return await this.cancelScan();
        case "confirm": return await this.answerConfirm(msg.id, msg.accept);
        case "newSession": return await this.newSession();
        case "switchSession": return await this.switchSession(msg.id);
        case "renameSession": return await this.renameSession(msg.id, msg.name);
        case "deleteSession": return await this.deleteSession(msg.id);
        case "openFinding": return await this.openFinding(msg.id);
        case "runCommand":
          if (msg.command.startsWith("vulnScanner.")) await vscode.commands.executeCommand(msg.command);
          return;
      }
    } catch (e) {
      this.showError(e);
    }
  }

  showError(e: unknown) {
    const err = e as Error;
    if (e instanceof CancelledError || err?.name === "AbortError") return;
    if (e instanceof TokenRejectedError) {
      this.setDisconnected(e);
      this.post({ type: "error", message: TOKEN_REJECTED, action: { label: "Set Token", command: "vulnScanner.setToken" } });
      return;
    }
    if (e instanceof ServerUnreachableError) this.setDisconnected(e);
    const known = e instanceof ToolCallError || e instanceof UploadError || e instanceof TooLargeError
      || e instanceof ServerUnreachableError;
    if (!known) log.error(`Unexpected error: ${err?.stack ?? err}`);
    this.post({ type: "error", message: err?.message || String(e) });
  }

  /** Every message goes to the agent, which answers and may ask us to start or stop a scan.
   * If the agent is unavailable, simple keyword rules still recognise scan commands. */
  async send(text: string) {
    text = text.trim();
    if (!text) return;
    this.say(text, "user");
    const client = await this.ready();
    if (!this.current) await this.useSession(await this.createSession("workspace"));
    this.post({ type: "thinking", on: true });
    let reply;
    try {
      reply = await client.chat(this.current!, text);
    } catch (e) {
      const err = e as Error;
      const fallback = e instanceof ToolCallError && /\bLLM\b/.test(err.message) ? keywordAction(text) : null;
      if (!fallback) throw e;
      this.post({ type: "thinking", on: false });
      log.warn(`Agent unavailable (${err.message}); using keyword rules`);
      this.say(`The assistant is unavailable right now (${err.message}), but this looks like a scan request.`);
      return this.runAction(fallback);
    } finally {
      this.post({ type: "thinking", on: false });
    }
    this.post({ type: "message", message: { role: "assistant", text: reply.reply, finding_ids: reply.finding_ids } });
    if (reply.action) await this.offerAction(reply.action);
  }

  private pending = new Map<string, () => Promise<void>>();
  private editedWithFindings = new Set<string>();
  private alreadySuggested = new Set<string>();
  private suggestTimer?: NodeJS.Timeout;

  /** After you save files that have findings, offer a rescan (once per file until the next scan). */
  onSaved(uri: vscode.Uri) {
    const s = this.currentSession();
    if (!s || s.target_type !== "workspace" || uri.scheme !== "file") return;
    const folder = this.sessionFolder(s.session_id);
    if (!folder) return;
    const rel = path.relative(folder, uri.fsPath).split(path.sep).join("/");
    if (rel.startsWith("..") || this.alreadySuggested.has(rel) || !this.findings.some((f) => f.path === rel)) return;
    this.editedWithFindings.add(rel);
    clearTimeout(this.suggestTimer);
    this.suggestTimer = setTimeout(() => this.suggestRescan(), SUGGEST_RESCAN_AFTER_MS);
  }

  private suggestRescan() {
    if (this.scanning || this.busy || !this.editedWithFindings.size) return;
    const files = [...this.editedWithFindings];
    this.editedWithFindings.clear();
    files.forEach((f) => this.alreadySuggested.add(f));
    const list = files.slice(0, 3).map((f) => `\`${f}\``).join(", ") + (files.length > 3 ? ` and ${files.length - 3} more` : "");
    this.say(`You changed ${files.length === 1 ? "a file" : `${files.length} files`} with findings (${list}). `
      + "Want me to rescan to see if they are fixed?");
    this.ask("Rescan", () => this.rescan());
  }

  /** Run an action, or ask first with Yes/No buttons when the agent was not sure. */
  private async offerAction(action: ChatAction) {
    if (!action.confirm) return this.runAction(action);
    this.ask(action.type === "cancel" ? "Stop the scan" : "Yes, scan", () => this.runAction(action));
  }

  private ask(yes: string, onYes: () => Promise<void>, no = "No") {
    const id = Math.random().toString(36).slice(2);
    this.pending.set(id, onYes);
    this.post({ type: "confirm", id, yes, no });
  }

  private async answerConfirm(id: string, accept: boolean) {
    const run = this.pending.get(id);
    this.pending.delete(id);
    this.post({ type: "confirmDone", id });
    if (!run) return;
    if (accept) await run();
    else this.say("OK, I won't.");
  }

  private async runAction(a: ChatAction) {
    const opts = { full: a.full, paths: a.paths };
    switch (a.type) {
      case "cancel": return this.cancelScan();
      case "scan_github": return this.scanGithub(a.url!, opts);
      case "scan_workspace": return this.scanWorkspace(opts);
      case "scan": return this.rescan(opts);
    }
  }

  // --- sessions ---

  private async refreshSessions() {
    const client = await this.ready();
    this.sessions = (await client.listSessions()).sessions;
    this.postState();
  }

  private async createSession(type: "workspace" | "github", repoUrl?: string): Promise<string> {
    const client = await this.ready();
    const name = type === "workspace" ? vscode.workspace.workspaceFolders?.[0]?.name : undefined;
    const { session_id } = await client.createSession(type, repoUrl, name);
    await this.refreshSessions();
    return session_id;
  }

  private async useSession(id: string) {
    this.current = id;
    await this.ctx.workspaceState.update(this.lastSessionKey(), id);
    this.postState();
  }

  async newSession() {
    await this.switchSession(await this.createSession("workspace"));
  }

  async switchSession(id: string) {
    await this.useSession(id);
    await this.showSession(id);
  }

  private async showSession(id: string) {
    const client = await this.ready();
    const detail = await client.getSession(id);
    this.post({ type: "history", messages: detail.messages });
    await this.loadFindings();
  }

  async renameSession(id: string, name: string) {
    if (!name.trim()) return;
    await (await this.ready()).renameSession(id, name.trim());
    await this.refreshSessions();
  }

  async deleteSession(id: string) {
    const s = this.sessions.find((x) => x.session_id === id);
    const answer = await vscode.window.showWarningMessage(
      `Delete the session "${s?.name ?? id}"? Its history and findings are removed from the server.`,
      { modal: true }, "Delete");
    if (answer !== "Delete") return;
    if (this.scanning?.sessionId === id) this.scanning.abort.abort();
    await (await this.ready()).deleteSession(id);
    if (this.current === id) {
      this.current = null;
      await this.ctx.workspaceState.update(this.lastSessionKey(), undefined);
      this.findings = [];
      this.diagnostics.clear();
      this.post({ type: "history", messages: [] });
      this.post({ type: "findings", findings: [], hidden: 0, total: 0 });
    }
    await this.refreshSessions();
  }

  private currentSession() {
    return this.sessions.find((s) => s.session_id === this.current);
  }

  private sessionFolder(sessionId: string): string | undefined {
    const map = this.ctx.workspaceState.get<Record<string, string>>(SESSION_FOLDERS_KEY, {});
    const folders = vscode.workspace.workspaceFolders ?? [];
    const mapped = map[sessionId];
    if (mapped && folders.some((f) => f.uri.fsPath === mapped)) return mapped;
    return folders.length === 1 ? folders[0].uri.fsPath : undefined;
  }

  private async mapSessionFolder(sessionId: string, folder: string) {
    const map = this.ctx.workspaceState.get<Record<string, string>>(SESSION_FOLDERS_KEY, {});
    await this.ctx.workspaceState.update(SESSION_FOLDERS_KEY, { ...map, [sessionId]: folder });
  }

  // --- scans ---

  private async pickFolder(): Promise<string | undefined> {
    const folders = vscode.workspace.workspaceFolders ?? [];
    if (folders.length === 0) {
      this.say("No folder is open. Open a folder, then ask me to scan it.");
      return undefined;
    }
    if (folders.length === 1) return folders[0].uri.fsPath;
    const pick = await vscode.window.showWorkspaceFolderPick({ placeHolder: "Which folder should be scanned?" });
    return pick?.uri.fsPath;
  }

  private ensureNotScanning() {
    if (this.scanning) throw new ToolCallError("A scan is already running. Wait for it, or click Cancel.");
  }

  /** Scan the current session's target again: the GitHub repo, or the workspace. */
  async rescan(opts: ScanOptions = {}) {
    const s = this.currentSession();
    if (s?.target_type === "github" && s.repo_url) return this.scanGithub(s.repo_url, opts);
    return this.scanWorkspace(opts);
  }

  /** Workspace scan: upload what changed, then scan. With nothing changed and no full or folder
   * scan asked for, it stops early. */
  async scanWorkspace(opts: ScanOptions = {}) {
    this.ensureNotScanning();
    const client = await this.ready();
    const folder = await this.pickFolder();
    if (!folder) return;

    let s = this.currentSession();
    if (!s || s.target_type !== "workspace" || (this.sessionFolder(s.session_id) ?? folder) !== folder) {
      await this.useSession(await this.createSession("workspace"));
      s = this.currentSession();
    }
    const sessionId = s!.session_id;
    await this.mapSessionFolder(sessionId, folder);

    const abort = new AbortController();
    this.busy = true;
    this.postState();
    try {
      const settings = this.settings();
      const prepared = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification, title: "Vuln Scanner", cancellable: true,
      }, async (progress, token) => {
        token.onCancellationRequested(() => abort.abort());
        progress.report({ message: "Looking at your files..." });
        let lastPct = 0;
        return prepareWorkspace(client, sessionId, folder, settings, {
          walking: (n) => progress.report({ message: `Hashing files: ${n} seen` }),
          uploading: (sent, total) => {
            const pct = Math.floor((sent / total) * 100);
            if (pct > lastPct) {
              progress.report({ message: `Uploading ${formatBytes(total)}: ${pct}%`, increment: pct - lastPct });
              lastPct = pct;
            }
          },
          isCancelled: () => token.isCancellationRequested,
          signal: abort.signal,
        });
      });
      const extra = { full: opts.full || undefined, paths: opts.paths?.length ? opts.paths : undefined };
      if (prepared.nothingChanged) {
        if (prepared.fileCount === 0) {
          this.say("There are no files to scan in this folder.");
          return;
        }
        if (extra.full || extra.paths) {
          const { scan_id } = await client.startScan(sessionId, extra);
          await this.follow(client, sessionId, scan_id);
          return;
        }
        // Skip only when the last scan finished; after a failed or cancelled one, scan again.
        if ((await client.getSession(sessionId)).session.last_scan_status === "done") {
          this.say("No files changed since the last scan.");
          return;
        }
        this.say("No files changed, but the last scan did not finish. Scanning again.");
        const { scan_id } = await client.startScan(sessionId, { full: true });
        await this.follow(client, sessionId, scan_id);
        return;
      }
      log.info(`Uploaded ${prepared.uploaded.length} files, ${prepared.deleted.length} deleted`);
      this.say(prepared.uploaded.length
        ? `Uploaded ${prepared.uploaded.length} changed file${prepared.uploaded.length === 1 ? "" : "s"}`
          + `${prepared.deleted.length ? ` (${prepared.deleted.length} deleted)` : ""}. Starting the scan.`
        : `${prepared.deleted.length} files were deleted. Starting the scan.`);
      const { scan_id } = await client.startScan(sessionId, { upload_id: prepared.uploadId,
                                                               deleted_paths: prepared.deleted, ...extra });
      await this.follow(client, sessionId, scan_id);
    } finally {
      this.busy = false;
      this.postState();
    }
  }

  async scanGithub(url: string, opts: ScanOptions = {}) {
    this.ensureNotScanning();
    const client = await this.ready();
    let s = this.currentSession();
    const norm = (u: string | null) => (u ?? "").replace(/\.git$/, "").replace(/\/+$/, "").toLowerCase();
    if (!s || s.target_type !== "github" || norm(s.repo_url) !== norm(url)) {
      await this.useSession(await this.createSession("github", url));
      s = this.currentSession();
    }
    const { scan_id } = await client.startScan(s!.session_id, {
      full: opts.full || undefined, paths: opts.paths?.length ? opts.paths : undefined });
    await this.follow(client, s!.session_id, scan_id);
  }

  private async follow(client: HarnessClient, sessionId: string, scanId: string) {
    const abort = new AbortController();
    this.scanning = { scanId, sessionId, abort };
    this.postState();
    try {
      this.post({ type: "progress", percent: 0, message: "Scan started" });
      const live = this.liveFindings(sessionId, scanId);
      const summary = await watchToEnd(client, scanId, (percent, message) => {
        this.post({ type: "progress", percent, message });
        live.poke();
      }, abort.signal);
      await live.stop();
      this.post({ type: "progress", percent: summary.percent, message: summary.status, done: true });
      if (summary.status === "done") {
        await this.loadFindings();
        const newCount = this.findings.filter((f) => f.status === "new").length;
        this.say(scanSummaryText(summary.counts, newCount, summary.error));
      } else if (summary.status === "cancelled") {
        this.say("The scan was cancelled.");
      } else {
        this.post({ type: "error", message: `The scan failed: ${summary.error ?? "unknown error"}` });
      }
    } finally {
      this.scanning = null;
      this.alreadySuggested.clear();
      this.editedWithFindings.clear();
      await this.refreshSessions().catch(() => undefined);
      this.postState();
    }
  }

  /** Refresh the findings of a running scan as progress arrives: at most one fetch at a time,
   * and at most every LIVE_REFRESH_MS, so a busy scan does not flood the server. */
  private liveFindings(sessionId: string, scanId: string) {
    let running: Promise<void> | null = null;
    let again = false;
    let last = 0;
    let timer: NodeJS.Timeout | undefined;
    let stopped = false;
    const run = () => {
      if (stopped || this.current !== sessionId) return;
      if (running) {
        again = true;
        return;
      }
      last = Date.now();
      running = this.loadFindings(scanId).catch((e) => log.warn(`Live findings refresh failed: ${(e as Error).message}`))
        .finally(() => {
          running = null;
          if (again) {
            again = false;
            poke();
          }
        });
    };
    const poke = () => {
      if (timer || stopped) return;
      timer = setTimeout(() => {
        timer = undefined;
        run();
      }, Math.max(0, LIVE_REFRESH_MS - (Date.now() - last)));
    };
    return {
      poke,
      stop: async () => {
        stopped = true;
        clearTimeout(timer);
        await running;
      },
    };
  }

  async cancelScan() {
    if (!this.scanning) {
      this.say("No scan is running.");
      return;
    }
    await (await this.ready()).cancelScan(this.scanning.scanId);
  }

  // --- findings ---

  /** Findings of the latest finished scan, or of `scanId` while it runs. */
  async loadFindings(scanId?: string) {
    if (!this.current) return;
    const client = await this.ready();
    const sessionId = this.current;
    const list = await fetchAllFindings(client, sessionId, scanId);
    if (this.current !== sessionId) return;
    this.findings = sortFindings(list);
    const folder = this.currentSession()?.target_type === "workspace" ? this.sessionFolder(sessionId) : undefined;
    const views: FindingView[] = await Promise.all(this.findings.map(async (f) => ({
      ...f, outdated: folder ? await this.isOutdated(folder, f) : false,
    })));
    const { shown, hidden } = splitHidden(views, this.settings().showLikelyFalsePositives);
    this.post({ type: "findings", findings: shown, hidden, total: views.length });
    this.updateDiagnostics(folder, shown);
  }

  private async isOutdated(folder: string, f: Finding) {
    try {
      return (await hashFile(path.join(folder, f.path))) !== f.file_sha256;
    } catch {
      return true;
    }
  }

  private updateDiagnostics(folder: string | undefined, findings: Finding[]) {
    this.diagnostics.clear();
    if (!folder) return;
    const byFile = new Map<string, vscode.Diagnostic[]>();
    for (const f of findings) {
      const range = new vscode.Range(f.start_line - 1, (f.start_col ?? 1) - 1, f.end_line - 1,
                                     f.end_col != null ? f.end_col : Number.MAX_SAFE_INTEGER);
      const level = { error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning,
                      information: vscode.DiagnosticSeverity.Information }[diagnosticLevel(f.severity)];
      const d = new vscode.Diagnostic(range, diagnosticMessage(f), level);
      d.source = "Vuln Scanner";
      d.code = f.rule_id;
      const list = byFile.get(f.path) ?? [];
      list.push(d);
      byFile.set(f.path, list);
    }
    for (const [rel, list] of byFile) this.diagnostics.set(vscode.Uri.file(path.join(folder, rel)), list);
  }

  getDiagnostics() {
    const out: [vscode.Uri, readonly vscode.Diagnostic[]][] = [];
    this.diagnostics.forEach((uri, list) => { out.push([uri, list]); });
    return out;
  }

  async onSettingsChanged(e: vscode.ConfigurationChangeEvent) {
    if (["serverUrl", "token", "caCertificate"].some((k) => e.affectsConfiguration(`vulnScanner.${k}`))) {
      // Our own clearing of the token setting also lands here; only reconnect when there is something to use.
      if (e.affectsConfiguration("vulnScanner.token")
          && !vscode.workspace.getConfiguration("vulnScanner").get<string>("token")?.trim()) return;
      await this.connect();
    }
    else if (e.affectsConfiguration("vulnScanner.showLikelyFalsePositives") && this.client) await this.loadFindings();
  }

  async openFinding(id: string) {
    const f = this.findings.find((x) => x.id === id);
    if (!f) return;
    const s = this.currentSession();
    if (s?.target_type === "github") {
      if (f.web_url) await vscode.env.openExternal(vscode.Uri.parse(f.web_url));
      return;
    }
    const folder = this.current ? this.sessionFolder(this.current) : undefined;
    if (!folder) {
      this.say("I don't know which folder this session belongs to. Open that folder and rescan.");
      return;
    }
    const uri = vscode.Uri.file(path.join(folder, f.path));
    try {
      await vscode.workspace.fs.stat(uri);
    } catch {
      this.post({ type: "error", message: `${f.path} no longer exists. Click Rescan to update.` });
      return;
    }
    if (await this.isOutdated(folder, f)) {
      void vscode.window.showInformationMessage(
        "This file changed since the scan. The line may have moved. Click Rescan to update.");
    }
    const doc = await vscode.workspace.openTextDocument(uri);
    const end = doc.lineAt(Math.min(f.end_line, doc.lineCount) - 1).range.end;
    const start = new vscode.Position(Math.min(f.start_line, doc.lineCount) - 1, 0);
    await vscode.window.showTextDocument(doc, { selection: new vscode.Range(start, end), preview: false });
  }
}
