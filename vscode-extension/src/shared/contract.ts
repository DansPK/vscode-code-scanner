// Types from the shared contract between the extension and the harness.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface ManifestEntry {
  path: string;
  sha256: string;
  size: number;
}

export interface SessionInfo {
  session_id: string;
  name: string;
  target_type: "workspace" | "github";
  repo_url: string | null;
  created_at: string;
  last_scan_at: string | null;
  last_scan_status: string | null;
}

export interface ChatMessage {
  role: "user" | "assistant";
  text: string;
  finding_ids: string[];
  created_at?: string;
}

export interface SessionDetail {
  session: SessionInfo;
  messages: ChatMessage[];
  latest_scan_id: string | null;
  file_count: number;
}

export interface SyncResult {
  need: string[];
  delete: string[];
  unchanged_count: number;
}

export interface UploadTicket {
  upload_id: string;
  upload_url: string;
  expires_at: string;
}

export type ScanStatus = "queued" | "running" | "done" | "failed" | "cancelled";

export interface ScanSummary {
  scan_id: string;
  session_id: string;
  status: ScanStatus;
  stage: string;
  percent: number;
  counts: Partial<Record<Severity, number>>;
  error: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: string;
  tools: string[];
  rule_id: string;
  title: string;
  severity: Severity;
  cwe: string | null;
  path: string;
  start_line: number;
  end_line: number;
  start_col: number | null;
  end_col: number | null;
  file_sha256: string;
  message: string;
  snippet: string;
  verdict: "likely_real" | "likely_false_positive" | "unsure";
  explanation: string;
  fix_recommendation: string;
  suggested_patch: string | null;
  status: "new" | "existing";
  web_url: string | null;
}

export interface FindingsPage {
  findings: Finding[];
  total: number;
}

/** What the agent decided the user wants; the extension carries it out (only it can upload files). */
export interface ChatAction {
  /** scan: the current session's target; scan_workspace: the local workspace (from a GitHub session);
   * scan_github: the repo in `url`; cancel: stop the running scan; fix: fix `finding_ids` with fix_findings. */
  type: "scan" | "scan_workspace" | "scan_github" | "cancel" | "fix";
  full: boolean;
  /** Folders or files to limit the scan to; empty for everything. */
  paths: string[];
  url: string | null;
  /** Ask the user first: the agent only thinks this is wanted. */
  confirm: boolean;
  /** For fix: the findings to fix, most serious first. */
  finding_ids: string[];
}

/** Replace lines start_line..end_line (1-based, inclusive) with `replacement` ("" deletes them). */
export interface FixEdit {
  start_line: number;
  end_line: number;
  replacement: string;
}

/** The fix agent's changes to one file. They apply only to the file whose hash is `file_sha256`. */
export interface FileFix {
  path: string;
  file_sha256: string;
  edits: FixEdit[];
}

/** fixed: the scanners no longer report it; still_reported: they still do; not_verified: changed, but
 * SonarQube cannot recheck one file; not_fixed: its file was not changed (`note` says why). */
export interface FixOutcome {
  finding_id: string;
  status: "fixed" | "still_reported" | "not_verified" | "not_fixed";
  note: string;
}

/** One progress event of fix_findings (its progress `message` is this, as JSON). Text and thinking
 * stream in pieces to append; heartbeat events only keep the request alive. */
export interface AgentEvent {
  file: string | null;
  kind: "start" | "thinking" | "text" | "tool" | "result" | "status" | "done" | "heartbeat";
  text: string;
}

/** What fix_findings returns. */
export interface FixResult {
  files: FileFix[];
  summary: string;
  results: FixOutcome[];
}

export interface ChatReply {
  reply: string;
  finding_ids: string[];
  action?: ChatAction | null;
}
