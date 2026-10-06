// Pure helpers for showing findings (no VS Code API here, so they can be unit tested).

import { AgentEvent, Finding, FixEdit, SEVERITIES } from "./shared/contract";

export function sortFindings<T extends Finding>(findings: T[]): T[] {
  return [...findings].sort((a, b) =>
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.path.localeCompare(b.path) || a.start_line - b.start_line);
}

export function splitHidden<T extends Finding>(findings: T[], showFalsePositives: boolean) {
  if (showFalsePositives) return { shown: findings, hidden: 0 };
  const shown = findings.filter((f) => f.verdict !== "likely_false_positive");
  return { shown, hidden: findings.length - shown.length };
}

export type Level = "error" | "warning" | "information";

export function diagnosticLevel(severity: Finding["severity"]): Level {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "information";
}

export function firstSentence(text: string): string {
  const t = (text ?? "").trim();
  const m = t.match(/^[\s\S]*?[.!?](?=\s|$)/);
  return (m ? m[0] : t).replace(/\s+/g, " ").trim();
}

export function diagnosticMessage(f: Finding): string {
  const fix = firstSentence(f.fix_recommendation);
  return fix ? `${f.title}: ${fix}` : f.title;
}

export function scanSummaryText(counts: Partial<Record<string, number>>, newCount: number, error: string | null,
                                hidden = 0): string {
  const total = Object.values(counts).reduce<number>((a, b) => a + (b ?? 0), 0);
  const parts = SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  let text = total ? `Scan finished: **${total} findings** (${parts.join(", ")}), ${newCount} new.`
    : "Scan finished: **no findings**.";
  if (hidden) {
    const which = hidden >= total ? (total === 1 ? "It looks like a false alarm" : "All of them look like false alarms")
      : `${hidden} of them look like false alarms`;
    text += ` ${which}, so ${hidden === 1 ? "it is" : "they are"} hidden in the Findings tab.`;
  }
  if (error) text += `\n\nSome steps had problems: ${error}`;
  return text;
}

/** Edits from several fixes of one file, sorted, without the ones that overlap an earlier edit. */
export function mergeEdits(edits: FixEdit[]): { kept: FixEdit[]; dropped: FixEdit[] } {
  const kept: FixEdit[] = [];
  const dropped: FixEdit[] = [];
  for (const e of [...edits].sort((a, b) => a.start_line - b.start_line || a.end_line - b.end_line)) {
    const last = kept[kept.length - 1];
    if (last && e.start_line <= last.end_line) dropped.push(e);
    else kept.push(e);
  }
  return { kept, dropped };
}

/** Apply non-overlapping line edits to a file's text, keeping its line endings. */
export function applyEdits(text: string, edits: FixEdit[]): string {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  for (const e of [...edits].sort((a, b) => b.start_line - a.start_line)) {
    if (e.start_line < 1 || e.end_line < e.start_line || e.end_line > lines.length) {
      throw new Error(`lines ${e.start_line}-${e.end_line} are outside the file`);
    }
    lines.splice(e.start_line - 1, e.end_line - e.start_line + 1,
                 ...(e.replacement === "" ? [] : e.replacement.split(/\r?\n/)));
  }
  return lines.join(eol);
}

/** A fix_findings progress message as an event. Plain text (an older harness) becomes a status line. */
export function parseAgentEvent(message: string): AgentEvent {
  try {
    const e = JSON.parse(message);
    if (e && typeof e.kind === "string" && typeof e.text === "string") return e as AgentEvent;
  } catch { /* not JSON */ }
  return { file: null, kind: "status", text: message };
}
