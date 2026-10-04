// Pure helpers for showing findings (no VS Code API here, so they can be unit tested).

import { Finding, SEVERITIES } from "./shared/contract";

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

export function scanSummaryText(counts: Partial<Record<string, number>>, newCount: number, error: string | null): string {
  const total = Object.values(counts).reduce<number>((a, b) => a + (b ?? 0), 0);
  const parts = SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`);
  let text = total ? `Scan finished: **${total} findings** (${parts.join(", ")}), ${newCount} new.`
    : "Scan finished: **no findings**.";
  if (error) text += `\n\nSome steps had problems: ${error}`;
  return text;
}
