// Messages between the extension and the webview. The webview never talks to the harness.

import type { AgentEvent, ChatMessage, Finding, SessionInfo } from "./contract";

export type ConnectionStatus =
  | { state: "connected" }
  | { state: "connecting" }
  | { state: "disconnected"; reason: string; action?: { label: string; command: string } };

export type ToExtension =
  | { type: "ready" }
  | { type: "send"; text: string }
  | { type: "cancel" }
  | { type: "confirm"; id: string; accept: boolean }
  | { type: "newSession" }
  | { type: "switchSession"; id: string }
  | { type: "renameSession"; id: string; name: string }
  | { type: "deleteSession"; id: string }
  | { type: "openFinding"; id: string }
  | { type: "fix"; ids: string[] }
  | { type: "showFalsePositives"; on: boolean }
  | { type: "runCommand"; command: string };

export interface FindingView extends Finding {
  /** The file changed since the scan, so lines may have moved. */
  outdated?: boolean;
}

export type ToWebview =
  | { type: "state"; connection: ConnectionStatus; sessions: SessionInfo[]; current: string | null;
      scanning: boolean; busy: boolean;
      /** Saved files with findings since the last scan: the Rescan button lights up. */
      changed: number }
  | { type: "history"; messages: ChatMessage[] }
  | { type: "message"; message: ChatMessage }
  | { type: "progress"; percent: number; message: string; done?: boolean }
  | { type: "findings"; findings: FindingView[]; hidden: number; total: number }
  | { type: "thinking"; on: boolean }
  /** Yes/No buttons under the last assistant message; the answer comes back as a `confirm` message. */
  | { type: "confirm"; id: string; yes: string; no: string }
  | { type: "confirmDone"; id: string }
  /** The fix agent's live transcript: a block in the chat, then events appended to it as they stream in. */
  | { type: "agentStart"; id: string; title: string }
  | { type: "agentEvent"; id: string; event: AgentEvent }
  | { type: "agentEnd"; id: string; title: string }
  | { type: "error"; message: string; action?: { label: string; command: string } };
