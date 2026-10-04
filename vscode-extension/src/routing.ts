// Decide what a chat message asks for. Rules are checked in order; keep them here so they are easy to change.

export type Route =
  | { kind: "github"; url: string }
  | { kind: "rescan" }
  | { kind: "scan" }
  | { kind: "chat" };

const GITHUB = /https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+/;
const RESCAN = /\brescan\b|\bscan\s+again\b|\bre-scan\b/i;
const SCAN_VERB = /\b(scan|analy[sz]e|check)\b/i;
const SCAN_OBJECT = /\b(this|project|workspace|code|folder)\b/i;

export function route(text: string): Route {
  const gh = text.match(GITHUB);
  if (gh) return { kind: "github", url: gh[0].replace(/[.,;:!?)]+$/, "").replace(/\.git$/, "") };
  if (RESCAN.test(text)) return { kind: "rescan" };
  if (SCAN_VERB.test(text) && SCAN_OBJECT.test(text)) return { kind: "scan" };
  return { kind: "chat" };
}
