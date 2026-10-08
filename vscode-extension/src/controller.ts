// Ties VS Code to the harness: connection, sessions, chat, scans, findings and editor markers.

import * as path from "path";
import * as vscode from "vscode";
import { formatBytes } from "./archive";
import { HarnessClient, ServerUnreachableError, TOKEN_REJECTED, TokenRejectedError, ToolCallError } from "./client";
import { applyEdits, diagnosticLevel, diagnosticMessage, mergeEdits, parseAgentEvent, scanSummaryText, sortFindings,
  splitHidden } from "./findingsLogic";
import { makeFetch } from "./http";
import { log } from "./log";
import { route } from "./routing";
import { fetchAllFindings, prepareWorkspace, TooLargeError, watchToEnd } from "./scanFlow";
import type { ChatAction, ChatMessage, FileFix, Finding, FixOutcome, FixResult, ScanSummary, SessionInfo }
  from "./shared/contract";
import type { ConnectionStatus, FindingView, ToExtension, ToWebview } from "./shared/messages";
import { UploadError } from "./upload";
import { CancelledError, hashFile } from "./workspaceFiles";

export const TOKEN_KEY = "vulnScanner.token";
const LAST_SESSION_KEY = "vulnScanner.lastSession";
const SESSION_FOLDERS_KEY = "vulnScanner.sessionFolders";
const PRIVATE_REPOS_KEY = "vulnScanner.privateRepoSessions"; // GitHub sessions that needed a sign-in
const PRIVATE_HINT = /If the repository is private, sign in to GitHub and scan again\./;

/** The user's GitHub token from VS Code's built-in GitHub sign-in ("repo" scope reads private repos).
 * Never stored or logged by the extension; passed to the harness for one download. */
async function githubToken(prompt: boolean): Promise<string | undefined> {
  try {
    const s = await vscode.authentication.getSession("github", ["repo"], prompt ? { createIfNone: true } : { silent: true });
    return s?.accessToken;
  } catch {
    return undefined; // cancelled, or no GitHub sign-in available
  }
}
const LIVE_REFRESH_MS = 1500;
const FIX_SCHEME = "vulnscanner-fix";
const OUTCOME_LABEL: Record<FixOutcome["status"], string> = {
  fixed: "✅ fixed:", still_reported: "⚠️ still reported:", not_verified: "🔎 changed, rescan to confirm:",
  not_fixed: "⏭️ not changed:",
};

export interface ScanOptions {
  full?: boolean;
  paths?: string[];
}

/** The keyword rules, used only when the agent cannot be reached. */
function keywordAction(text: string): ChatAction | null {
  const r = route(text);
  const base = { full: false, paths: [], url: null, confirm: false, finding_ids: [] };
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
  private hiddenCount = 0; // likely false alarms hidden by the setting
  private readonly diagnostics: vscode.DiagnosticCollection;
  private views: View[] = [];
  private connecting?: Promise<boolean>;
  /** Proposed file contents shown on the right of a fix diff, by virtual URI. */
  private readonly proposed = new Map<string, string>();
  private readonly fixDocs: vscode.Disposable;

  constructor(private readonly ctx: vscode.ExtensionContext) {
    this.diagnostics = vscode.languages.createDiagnosticCollection("vulnScanner");
    this.fixDocs = vscode.workspace.registerTextDocumentContentProvider(FIX_SCHEME, {
      provideTextDocumentContent: (uri) => this.proposed.get(uri.toString()) ?? "",
    });
  }

  dispose() {
    this.diagnostics.dispose();
    this.fixDocs.dispose();
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
                scanning: this.scanning !== null, busy: this.busy, changed: this.editedWithFindings.size });
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
        case "fix": return await this.fixFindings(msg.ids);
        case "showFalsePositives":
          return await vscode.workspace.getConfiguration("vulnScanner")
            .update("showLikelyFalsePositives", msg.on, vscode.ConfigurationTarget.Global);
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

  private pending = new Map<string, { onYes: () => Promise<void>; onNo?: () => void }>();
  private editedWithFindings = new Set<string>();

  /** Saved files that have findings light up the Rescan button (no chat message). */
  onSaved(uri: vscode.Uri) {
    const s = this.currentSession();
    if (!s || s.target_type !== "workspace" || uri.scheme !== "file") return;
    const folder = this.sessionFolder(s.session_id);
    if (!folder) return;
    const rel = path.relative(folder, uri.fsPath).split(path.sep).join("/");
    if (rel.startsWith("..") || this.editedWithFindings.has(rel) || !this.findings.some((f) => f.path === rel)) return;
    this.editedWithFindings.add(rel);
    this.postState();
  }

  /** Run an action, or ask first with Yes/No buttons when the agent was not sure. */
  private async offerAction(action: ChatAction) {
    if (!action.confirm) return this.runAction(action);
    const yes = { cancel: "Stop the scan", fix: "Yes, fix them" }[action.type as string] ?? "Yes, scan";
    this.ask(yes, () => this.runAction(action));
  }

  private ask(yes: string, onYes: () => Promise<void>, no = "No", onNo?: () => void) {
    const id = Math.random().toString(36).slice(2);
    this.pending.set(id, { onYes, onNo });
    this.post({ type: "confirm", id, yes, no });
  }

  private async answerConfirm(id: string, accept: boolean) {
    const run = this.pending.get(id);
    this.pending.delete(id);
    this.post({ type: "confirmDone", id });
    if (!run) return;
    if (accept) await run.onYes();
    else if (run.onNo) run.onNo();
    else this.say("OK, I won't.");
  }

  private async runAction(a: ChatAction) {
    const opts = { full: a.full, paths: a.paths };
    switch (a.type) {
      case "fix": return this.fixFindings(a.finding_ids ?? []);
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
    const { session_id } = await client.createSession(type, repoUrl);
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
    const sessionId = s!.session_id;
    const start = (github_token?: string) => client.startScan(sessionId, {
      full: opts.full || undefined, paths: opts.paths?.length ? opts.paths : undefined, github_token });
    const privateRepos = this.ctx.workspaceState.get<string[]>(PRIVATE_REPOS_KEY, []);
    let token: string | undefined;
    if (privateRepos.includes(sessionId)) token = await githubToken(false); // signed in before: no prompt
    let scanId: string;
    try {
      scanId = (await start(token)).scan_id;
    } catch (e) {
      if (!(e instanceof ToolCallError && PRIVATE_HINT.test(e.message))) throw e;
      // GitHub refused without a sign-in: maybe a private repository. Offer VS Code's own GitHub sign-in.
      this.say(`${e.message.replace(PRIVATE_HINT, "").trim()}\n\nIf this is a private repository, sign in to `
        + "GitHub and I'll scan it with your account. The sign-in stays in VS Code; the scanner server uses it "
        + "for this download only and does not store it.");
      this.ask("Sign in to GitHub", async () => {
        const signedIn = await githubToken(true);
        if (!signedIn) {
          this.say("GitHub sign-in was cancelled.");
          return;
        }
        const { scan_id } = await start(signedIn);
        await this.ctx.workspaceState.update(PRIVATE_REPOS_KEY, [...new Set([...privateRepos, sessionId])]);
        await this.follow(client, sessionId, scan_id);
      }, "Not now");
      return;
    }
    await this.follow(client, sessionId, scanId);
  }

  /** After a scan: the harness's short summary, with what only the extension knows (hidden findings,
   * scan errors). If the summary cannot be made, the plain counts. */
  private async showScanSummary(client: HarnessClient, sessionId: string, counts: ScanSummary["counts"],
                                error: string | null) {
    this.post({ type: "thinking", on: true });
    try {
      const s = await client.summarizeFindings(sessionId);
      this.post({ type: "summaryCard", card: s.card, hidden: this.hiddenCount, error });
    } catch (e) {
      log.warn(`Summary failed: ${(e as Error).message}`);
      const newCount = this.findings.filter((f) => f.status === "new").length;
      this.say(scanSummaryText(counts, newCount, error, this.hiddenCount));
    } finally {
      this.post({ type: "thinking", on: false });
    }
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
        await this.showScanSummary(client, sessionId, summary.counts, summary.error);
      } else if (summary.status === "cancelled") {
        this.say("The scan was cancelled.");
      } else {
        this.post({ type: "error", message: `The scan failed: ${summary.error ?? "unknown error"}` });
      }
    } finally {
      this.scanning = null;
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
    this.hiddenCount = hidden;
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

  // --- auto-fix ---

  /** Let the fix agent on the harness fix findings, then show its changes: one file as a diff with
   * Apply/Skip; several files with a choice of applying all at once or reviewing them one by one.
   * Changes apply only to a saved file that still has the hash the agent worked from. */
  async fixFindings(ids: string[]) {
    if (!ids.length) return;
    const s = this.currentSession();
    if (s?.target_type !== "workspace") {
      this.say("Auto-fix works only for workspace sessions, because it changes files in your open folder.");
      return;
    }
    const folder = this.sessionFolder(s.session_id);
    if (!folder) {
      this.say("I don't know which folder this session belongs to. Open that folder and rescan.");
      return;
    }
    if (this.scanning) throw new ToolCallError("A scan is running. Fix findings after it finishes.");
    const client = await this.ready();
    const sessionId = s.session_id;

    let result: FixResult | undefined;
    const abort = new AbortController();
    const live = Math.random().toString(36).slice(2);
    const started = Date.now();
    let ended = "Fix agent stopped";
    this.busy = true;
    this.postState();
    this.post({ type: "agentStart", id: live, title: `Fix agent · ${ids.length} finding${ids.length === 1 ? "" : "s"}` });
    try {
      result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification,
                                                  title: "Vuln Scanner: fix agent", cancellable: true },
        async (progress, token) => {
          token.onCancellationRequested(() => abort.abort());
          let last = 0;
          return client.fixFindings(sessionId, ids, (percent, message) => {
            const event = parseAgentEvent(message);
            if (event.kind === "heartbeat") return;
            this.post({ type: "agentEvent", id: live, event });
            const line = event.kind === "tool" || event.kind === "status" || event.kind === "done"
              ? `${event.file ? `${path.basename(event.file)}: ` : ""}${event.text}` : undefined;
            progress.report({ message: line, increment: Math.max(0, percent - last) });
            last = Math.max(last, percent);
          }, abort.signal);
        });
      ended = `Fix agent finished in ${Math.round((Date.now() - started) / 1000)} s`;
    } finally {
      this.busy = false;
      this.post({ type: "agentEnd", id: live, title: ended });
      this.postState();
    }
    if (!result) return;

    const counts = { fixed: 0, still_reported: 0, not_verified: 0, not_fixed: 0 };
    for (const r of result.results) counts[r.status]++;
    const outcome = (r: FixOutcome) => `- ${OUTCOME_LABEL[r.status]} ${this.findingTitle(r.finding_id)}: ${r.note}`;
    const parts = [`**Fix agent:** ${counts.fixed} fixed and confirmed by the scanners`
      + (counts.not_verified ? `, ${counts.not_verified} changed but not rechecked (SonarQube)` : "")
      + (counts.still_reported ? `, ${counts.still_reported} still reported` : "")
      + (counts.not_fixed ? `, ${counts.not_fixed} not changed` : "") + "."];
    if (result.summary) parts.push(result.summary);
    const problems = result.results.filter((r) => r.status === "still_reported" || r.status === "not_fixed");
    if (problems.length) parts.push(problems.slice(0, 15).map(outcome).join("\n"));
    this.say(parts.join("\n\n"));

    const files = [...result.files].sort((x, y) => x.path.localeCompare(y.path));
    const byPath = new Map(result.results.map((r) => [r.finding_id, r]));
    const review = () => void this.reviewFileFixes(folder, files, byPath).catch((e) => this.showError(e));
    if (files.length === 1) return review();
    if (!files.length) return;
    this.say(`The agent changed ${files.length} files. Apply them all now, or review each file's diff first? `
      + "(Ctrl+Z in each file undoes a change.)");
    this.ask(`Apply all (${files.length} files)`, () => this.applyAllFixes(folder, files), "Review one by one", review);
  }

  private findingTitle(id: string) {
    const f = this.findings.find((x) => x.id === id);
    return f ? `**${f.title}** (${f.path}:${f.start_line})` : `\`${id}\``;
  }

  /** The fixed text of one file, or a reason it cannot be changed now. */
  private async prepareFileFix(folder: string, fix: FileFix) {
    const rel = fix.path;
    const uri = vscode.Uri.file(path.join(folder, rel));
    let doc: vscode.TextDocument;
    try {
      doc = await vscode.workspace.openTextDocument(uri);
    } catch {
      return { problem: `\`${rel}\` no longer exists.` };
    }
    if (doc.isDirty) return { problem: `\`${rel}\` has unsaved changes. Save it, rescan, and ask again.` };
    if ((await hashFile(uri.fsPath)) !== fix.file_sha256) {
      return { problem: `\`${rel}\` changed since it was last uploaded, so the change may not fit. Rescan, then ask again.` };
    }
    const { kept, dropped } = mergeEdits(fix.edits);
    const original = doc.getText();
    try {
      return { uri, original, fixed: applyEdits(original, kept), kept, dropped };
    } catch (e) {
      return { problem: `The change to \`${rel}\` doesn't fit the file (${(e as Error).message}). Rescan, then ask again.` };
    }
  }

  /** Write the fixed text if the file is still what the fix was made for. Returns an error, or null. */
  private async writeFileFix(rel: string, fix: { uri: vscode.Uri; original: string; fixed: string; kept: unknown[] }) {
    const now = await vscode.workspace.openTextDocument(fix.uri);
    if (now.getText() !== fix.original) return `\`${rel}\` changed in the meantime. Ask again to get a fresh fix.`;
    const edit = new vscode.WorkspaceEdit();
    edit.replace(fix.uri, new vscode.Range(now.positionAt(0), now.positionAt(fix.original.length)), fix.fixed);
    if (!(await vscode.workspace.applyEdit(edit)) || !(await now.save())) return `Could not write \`${rel}\`.`;
    log.info(`Applied ${fix.kept.length} fix edit(s) to ${rel}`);
    return null;
  }

  private async applyAllFixes(folder: string, files: FileFix[]) {
    let applied = 0;
    const problems: string[] = [];
    for (const file of files) {
      const fix = await this.prepareFileFix(folder, file);
      const problem = "problem" in fix ? fix.problem : await this.writeFileFix(file.path, fix);
      if (problem) problems.push(`- ${problem}`);
      else applied++;
    }
    this.say(`Applied changes to ${applied} of ${files.length} files. Rescan to check them.`
      + (problems.length ? `\n\nNot applied:\n${problems.join("\n")}` : ""));
  }

  /** One file at a time: open its diff, wait for Apply or Skip, then go on to the next. */
  private async reviewFileFixes(folder: string, files: FileFix[], outcomes: Map<string, FixOutcome>) {
    for (const [i, file] of files.entries()) {
      const rel = file.path;
      const fix = await this.prepareFileFix(folder, file);
      if ("problem" in fix) {
        this.say(fix.problem!);
        continue;
      }
      const right = vscode.Uri.from({ scheme: FIX_SCHEME, path: `/${rel}`, query: Math.random().toString(36).slice(2) });
      this.proposed.set(right.toString(), fix.fixed);
      await vscode.commands.executeCommand("vscode.diff", fix.uri, right, `${path.basename(rel)}: proposed fix`,
                                           { preview: true });
      const here = this.findings.filter((f) => f.path === rel && outcomes.has(f.id))
        .map((f) => `- ${OUTCOME_LABEL[outcomes.get(f.id)!.status]} ${this.findingTitle(f.id)}`);
      if (fix.dropped.length) here.push(`- ${fix.dropped.length} overlapping edit(s) were left out.`);
      const counter = files.length > 1 ? ` (file ${i + 1} of ${files.length})` : "";
      this.say(`Proposed fix for \`${rel}\`${counter} (see the diff)${here.length ? `:\n${here.join("\n")}` : "."}`);
      await new Promise<void>((resolve) => this.ask("Apply fix", async () => {
        this.proposed.delete(right.toString());
        const problem = await this.writeFileFix(rel, fix);
        if (problem) this.post({ type: "error", message: problem.replace(/`/g, "") });
        else this.say(`Applied the fix to \`${rel}\` (Ctrl+Z in the editor undoes it).`
          + (i === files.length - 1 ? " Rescan to check it." : ""));
        resolve();
      }, "Skip", () => {
        this.proposed.delete(right.toString());
        this.say(`Skipped \`${rel}\`.`);
        resolve();
      }));
    }
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
