// The chat panel UI. It talks only to the extension, through postMessage.

import MarkdownIt from "markdown-it";
import type { AgentEvent, ChatMessage, SessionInfo, SummaryCard } from "../src/shared/contract";
import type { ConnectionStatus, FindingView, ToExtension, ToWebview } from "../src/shared/messages";

interface UiState {
  tab: "chat" | "findings";
  severities: string[]; // severities hidden by the filter chips
  query: string;
  collapsed: string[]; // collapsed severity groups
}

declare function acquireVsCodeApi(): {
  postMessage(msg: ToExtension): void;
  getState(): UiState | undefined;
  setState(s: UiState): void;
};
const vscode = acquireVsCodeApi();
const send = (msg: ToExtension) => vscode.postMessage(msg);
const md = new MarkdownIt({ html: false, linkify: true, breaks: true });

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const BADGE: Record<string, string> = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", info: "INFO" };
const VERDICT: Record<string, { label: string; cls: string }> = {
  likely_real: { label: "Likely real", cls: "real" },
  likely_false_positive: { label: "Likely false alarm", cls: "fp" },
  unsure: { label: "Unsure", cls: "unsure" },
};

const ui: UiState = { tab: "chat", severities: [], query: "", collapsed: [], ...(vscode.getState() ?? {}) };
const saveUi = () => vscode.setState(ui);

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {},
                                                   ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") e.textContent = v;
    else e.setAttribute(k, v);
  }
  e.append(...children);
  return e;
}

function button(label: string, cls: string, onClick: () => void, title = label) {
  const b = el("button", { class: cls, title, text: label });
  b.onclick = (e) => {
    e.stopPropagation();
    onClick();
  };
  return b;
}

// --- layout ---

const status = el("div", { class: "status" });
const sessionSelect = el("select", { "aria-label": "Session" });
const renameInput = el("input", { type: "text", class: "rename hidden", "aria-label": "New session name" });
const newBtn = el("button", { class: "secondary", title: "New session", text: "New" });
const renameBtn = el("button", { class: "secondary", title: "Rename session", text: "Rename" });
const deleteBtn = el("button", { class: "secondary", title: "Delete session", text: "Delete" });
const sessionBar = el("div", { class: "sessions" }, sessionSelect, renameInput, newBtn, renameBtn, deleteBtn);

const stopBtn = el("button", { class: "secondary small", title: "Stop the scan", text: "Stop" });
const progress = el("div", { class: "progress hidden" });
const progressBar = el("div", { class: "bar" });
const progressText = el("div", { class: "progress-text" });
progress.append(el("div", { class: "progress-row" }, progressText, stopBtn), el("div", { class: "track" }, progressBar));

const chatTab = el("button", { class: "tab", role: "tab", text: "Chat" });
const findingsTab = el("button", { class: "tab", role: "tab" });
const tabs = el("div", { class: "tabs", role: "tablist" }, chatTab, findingsTab);
const rescanBtn = el("button", { class: "secondary small rescan", text: "Rescan" });
const tabBar = el("div", { class: "tab-bar" }, tabs, rescanBtn);

// chat panel
const messages = el("div", { class: "messages", role: "log", "aria-live": "polite" });
const thinking = el("div", { class: "thinking hidden", text: "Thinking..." });
const input = el("textarea", { rows: "2", placeholder: "Ask anything, or tell me what to scan",
                               "aria-label": "Message" });
const sendBtn = el("button", { text: "Send" });
const composer = el("div", { class: "composer" }, input, el("div", { class: "send-row" },
  el("span", { class: "hint", text: "Enter to send, Shift+Enter for a new line" }), sendBtn));
const chatPanel = el("div", { class: "panel chat-panel" }, messages, thinking, composer);

// findings panel
const chips = el("div", { class: "chips" });
const search = el("input", { type: "search", class: "search", placeholder: "Filter by title, file, rule or CWE",
                             "aria-label": "Filter findings" });
const findingsNote = el("div", { class: "note" });
const findingsList = el("div", { class: "findings" });
const findingsEmpty = el("div", { class: "empty" });
const summarizeBtn = el("button", { class: "secondary small", title: "Ask the assistant for a summary of all findings",
                                    text: "Summarize" });
const fixAllBtn = el("button", { class: "secondary small",
                                title: "Fix every finding that is not a likely false alarm. You review the changes before they are applied.",
                                text: "Fix all" });
const findingsPanel = el("div", { class: "panel findings-panel" },
  el("div", { class: "filters" }, el("div", { class: "filter-row" }, chips, summarizeBtn, fixAllBtn), search),
  findingsNote, findingsList, findingsEmpty);

// Shown while the chat is empty: what you can say. Clicking one sends it (or starts it in the box).
const EXAMPLES: [string, boolean][] = [
  ["Scan this project", true],
  ["Scan only the ", false],
  ["Scan https://github.com/", false],
  ["What are the most serious problems?", true],
  ["Summarize all findings", true],
  ["Fix all high findings", true],
  ["Scan everything again from scratch", true],
];
const welcome = el("div", { class: "welcome" },
  el("div", { class: "welcome-title", text: "What would you like to do?" }),
  el("div", { class: "note", text: "Just type it. I can scan your workspace, a folder, or a GitHub repo, and answer questions about the findings." }));
const exampleList = el("div", { class: "examples" });
for (const [text, complete] of EXAMPLES) {
  const b = button(complete ? text : `${text}…`, "example", () => {
    if (complete) send({ type: "send", text });
    else {
      input.value = text;
      input.focus();
      input.setSelectionRange(text.length, text.length);
    }
  });
  exampleList.append(b);
}
welcome.append(exampleList);
messages.before(welcome);

document.getElementById("app")!.append(status, sessionBar, progress, tabBar, chatPanel, findingsPanel);

// --- state ---

let sessions: SessionInfo[] = [];
let current: string | null = null;
let scanning = false;
let changedFiles = 0;
let connected = false;
let findings: FindingView[] = [];
let hiddenFalsePositives = 0;
const expanded = new Set<string>();

function setTab(tab: UiState["tab"]) {
  ui.tab = tab;
  saveUi();
  chatTab.classList.toggle("active", tab === "chat");
  findingsTab.classList.toggle("active", tab === "findings");
  chatTab.setAttribute("aria-selected", String(tab === "chat"));
  findingsTab.setAttribute("aria-selected", String(tab === "findings"));
  chatPanel.classList.toggle("hidden", tab !== "chat");
  findingsPanel.classList.toggle("hidden", tab !== "findings");
  if (tab === "chat") messages.scrollTop = messages.scrollHeight;
}

function setStatus(c: ConnectionStatus) {
  connected = c.state === "connected";
  status.replaceChildren();
  status.className = `status ${c.state}`;
  if (c.state === "connected") status.append(el("span", { class: "dot" }), "Connected");
  else if (c.state === "connecting") status.append(el("span", { class: "dot" }), "Connecting...");
  else {
    status.append(el("span", { class: "dot" }), `${c.reason} `);
    if (c.action) status.append(actionButton(c.action));
  }
}

function actionButton(action: { label: string; command: string }) {
  return button(action.label, "link", () => send({ type: "runCommand", command: action.command }));
}

function updateControls() {
  stopBtn.classList.toggle("hidden", !scanning);
  sendBtn.disabled = !connected;
  newBtn.disabled = !connected;
  renameBtn.disabled = !connected || !current;
  deleteBtn.disabled = !connected || !current;
  sessionSelect.disabled = !connected || scanning;
  summarizeBtn.disabled = !connected || !findings.length;
  rescanBtn.disabled = !connected || scanning || !current;
  rescanBtn.classList.toggle("attention", changedFiles > 0);
  rescanBtn.textContent = changedFiles ? `Rescan · ${changedFiles} changed` : "Rescan";
  rescanBtn.title = changedFiles
    ? `${changedFiles} saved file${changedFiles === 1 ? " has" : "s have"} findings. Rescan to see if they are fixed.`
    : "Scan the files that changed since the last scan";
  fixAllBtn.disabled = !connected || scanning || !findings.length;
  fixAllBtn.classList.toggle("hidden", !isWorkspace());
}

function renderSessions() {
  sessionSelect.replaceChildren();
  if (!sessions.length) sessionSelect.append(el("option", { value: "", text: "No sessions yet" }));
  for (const s of sessions) {
    const label = `${s.name}${s.target_type === "github" ? " (GitHub)" : ""}`;
    const o = el("option", { value: s.session_id, text: label });
    if (s.session_id === current) o.selected = true;
    sessionSelect.append(o);
  }
  if (!current && sessions.length) sessionSelect.prepend(el("option", { value: "", text: "Choose a session", selected: "" }));
}

// --- chat messages ---

function addCopyButtons(root: HTMLElement) {
  root.querySelectorAll("pre").forEach((pre) => {
    const wrap = el("div", { class: "codewrap" });
    pre.replaceWith(wrap);
    wrap.append(pre, copyButton(() => pre.textContent ?? "", "copy"));
  });
}

function copyButton(text: () => string, cls = "secondary small", label = "Copy") {
  const b = button(label, cls, () => {
    void navigator.clipboard.writeText(text());
    b.textContent = "Copied";
    setTimeout(() => (b.textContent = label), 1500);
  });
  return b;
}

function renderMessage(m: ChatMessage) {
  const body = el("div", { class: "body" });
  if (m.role === "assistant") {
    body.innerHTML = md.render(m.text); // html is off, so the text cannot inject markup
    addCopyButtons(body);
  } else {
    body.textContent = m.text;
  }
  messages.append(el("div", { class: `msg ${m.role}` }, body));
  updateWelcome();
  messages.scrollTop = messages.scrollHeight;
}

function updateWelcome() {
  welcome.classList.toggle("hidden", messages.childElementCount > 0);
}

const confirmRows = new Map<string, HTMLElement>();

function renderConfirm(id: string, yes: string, no: string) {
  const answer = (accept: boolean) => {
    row.querySelectorAll("button").forEach((b) => ((b as HTMLButtonElement).disabled = true));
    send({ type: "confirm", id, accept });
  };
  const row = el("div", { class: "confirm" }, button(yes, "", () => answer(true)), button(no, "secondary", () => answer(false)));
  confirmRows.set(id, row);
  messages.append(row);
  messages.scrollTop = messages.scrollHeight;
}

// --- scan summary card ---

/** Open the Findings tab on one finding, expanded. */
function showFinding(id: string) {
  setTab("findings");
  ui.query = "";
  search.value = "";
  expanded.add(id);
  saveUi();
  renderFindings();
  findingsList.querySelector(`[data-id="${id}"]`)?.scrollIntoView({ block: "center" });
}

function showFile(path: string) {
  setTab("findings");
  ui.query = path;
  search.value = path;
  saveUi();
  renderFindings();
}

function renderSummaryCard(card: SummaryCard, hidden: number, error: string | null) {
  const root = el("div", { class: "summary-card" });
  const sub = card.total === 0 ? "No problems found."
    : card.false_alarms === card.total ? `All look like false alarms${hidden ? " (hidden)" : ""}.`
    : `${card.likely_real} likely real${card.false_alarms ? ` · ${card.false_alarms} false alarm${card.false_alarms === 1 ? "" : "s"}${hidden ? " (hidden)" : ""}` : ""}`;
  root.append(el("div", { class: "sc-head" },
    el("div", {},
      el("div", { class: `sc-title${card.total ? "" : " clean"}`, text: card.total ? "Scan complete" : "✓ No findings" }),
      el("div", { class: "sc-sub", text: sub })),
    el("div", { class: "sc-total" }, el("strong", { text: String(card.total) }),
       el("span", { text: card.total === 1 ? "finding" : "findings" }))));

  if (card.total) {
    const bar = el("div", { class: "sc-bar", role: "img",
      "aria-label": SEVERITIES.filter((s) => card.counts[s as keyof typeof card.counts])
        .map((s) => `${card.counts[s as keyof typeof card.counts]} ${s}`).join(", ") });
    const legend = el("div", { class: "sc-legend" });
    for (const s of SEVERITIES) {
      const n = card.counts[s as keyof typeof card.counts] ?? 0;
      if (!n) continue;
      const seg = el("span", { class: `sev-${s}` });
      seg.style.flexGrow = String(n);
      bar.append(seg);
      legend.append(el("span", { class: `sc-chip sev-${s}` }, el("span", { class: "sev-dot" }), `${n} ${s}`));
    }
    root.append(bar, legend);
  }

  const section = (label: string, ...children: Node[]) =>
    root.append(el("div", { class: "sc-section" }, el("div", { class: "sc-label", text: label }), ...children));
  if (card.overall) section("Overall", el("div", { class: "sc-overall", text: card.overall }));
  if (card.fix_first.length) {
    const list = el("ol", { class: "sc-fix" });
    card.fix_first.forEach((item, i) => {
      const id = item.finding_ids[0];
      const text = el(id ? "button" : "span", { class: "sc-fix-text", text: item.text,
                                               ...(id ? { title: "Show this finding" } : {}) });
      if (id) text.onclick = () => showFinding(id);
      const li = el("li", {}, el("span", { class: "sc-num", text: String(i + 1) }), text);
      if (id && isWorkspace()) {
        li.append(button("Fix", "secondary small", () => {
          setTab("chat");
          send({ type: "fix", ids: item.finding_ids });
        }, "Let the fix agent fix this"));
      }
      list.append(li);
    });
    section("Fix first", list);
  }
  if (card.files.length) {
    const files = el("div", { class: "sc-files" });
    for (const f of card.files) {
      const { dir, name } = splitPath(f.path);
      const row = button("", "sc-file", () => showFile(f.path), `Show the findings in ${f.path}`);
      row.append(el("span", { class: "sc-file-name", text: name }),
                 el("span", { class: "sc-file-dir" }, el("span", { dir: "ltr", text: dir.replace(/\/$/, "") })),
                 el("span", { class: "count", text: String(f.count) }));
      files.append(row);
    }
    section("Most affected", files);
  }
  if (error) root.append(el("div", { class: "sc-warn", text: `Some steps had problems: ${error}` }));

  const actions = el("div", { class: "sc-actions" });
  if (card.likely_real && isWorkspace()) {
    actions.append(button("Fix all", "", () => send({ type: "send", text: "Fix all findings" }),
                          "Let the fix agent fix every finding that is not a likely false alarm"));
  }
  if (card.total) actions.append(button("View findings", "secondary", () => setTab("findings")));
  if (actions.childElementCount) root.append(actions);

  messages.append(root);
  updateWelcome();
  messages.scrollTop = messages.scrollHeight;
}

// --- fix agent transcript ---

interface AgentBlock { root: HTMLDetailsElement; title: HTMLElement; body: HTMLElement; files: Map<string, HTMLElement> }
const agentBlocks = new Map<string, AgentBlock>();

function nearBottom() {
  return messages.scrollHeight - messages.scrollTop - messages.clientHeight < 80;
}

function agentStart(id: string, title: string) {
  const titleEl = el("span", { class: "agent-title", text: title });
  const body = el("div", { class: "agent-body" });
  const root = el("details", { class: "agent running", open: "" },
    el("summary", { class: "agent-head" }, el("span", { class: "spinner", "aria-hidden": "true" }), titleEl), body);
  agentBlocks.set(id, { root, title: titleEl, body, files: new Map() });
  messages.append(root);
  updateWelcome();
  messages.scrollTop = messages.scrollHeight;
}

/** Append one event: streamed text grows the last line of its kind, everything else is a new line. */
function agentEvent(id: string, e: AgentEvent) {
  const a = agentBlocks.get(id);
  if (!a) return;
  const follow = nearBottom();
  let section = a.body;
  if (e.file) {
    let s = a.files.get(e.file);
    if (!s) {
      s = el("div", { class: "agent-file" }, el("div", { class: "agent-file-name", text: e.file }));
      a.files.set(e.file, s);
      a.body.append(s);
    }
    section = s;
  }
  if (e.kind === "start") {
    section.querySelector(".agent-file-name")?.append(el("span", { class: "agent-dim", text: ` · ${e.text}` }));
  } else if (e.kind === "text" || e.kind === "thinking") {
    const last = section.lastElementChild;
    const line = last?.classList.contains(`agent-${e.kind}`) ? last as HTMLElement
      : section.appendChild(el("div", { class: `agent-${e.kind}` }));
    line.textContent += e.text;
    line.scrollTop = line.scrollHeight; // thinking scrolls inside its own box
  } else if (e.kind === "tool") {
    section.append(el("div", { class: "agent-tool" }, el("span", { class: "agent-bullet", text: "●" }), e.text));
  } else if (e.kind === "result") {
    section.append(el("div", { class: `agent-result${e.text.startsWith("Error") ? " error" : ""}`, text: `⎿ ${e.text}` }));
  } else if (e.kind === "done") {
    section.classList.add("done");
    a.title.dataset.progress = e.text;
  } else if (e.kind === "status") {
    section.append(el("div", { class: "agent-status", text: e.text }));
  }
  if (follow) messages.scrollTop = messages.scrollHeight;
}

function agentEnd(id: string, title: string) {
  const a = agentBlocks.get(id);
  if (!a) return;
  a.root.classList.remove("running");
  a.root.querySelector(".spinner")?.remove();
  a.title.textContent = title;
  agentBlocks.delete(id);
}

function showError(text: string, action?: { label: string; command: string }) {
  const box = el("div", { class: "msg error" }, el("span", { text }));
  if (action) box.append(" ", actionButton(action));
  messages.append(box);
  messages.scrollTop = messages.scrollHeight;
  setTab("chat");
}

// --- findings ---

function cap(s: string) {
  return s[0].toUpperCase() + s.slice(1);
}

function splitPath(p: string) {
  const i = p.lastIndexOf("/");
  return i < 0 ? { dir: "", name: p } : { dir: p.slice(0, i + 1), name: p.slice(i + 1) };
}

function matches(f: FindingView, q: string) {
  if (!q) return true;
  const hay = `${f.title} ${f.path} ${f.rule_id} ${f.cwe ?? ""} ${f.message} ${f.tools.join(" ")}`.toLowerCase();
  return q.toLowerCase().split(/\s+/).every((w) => hay.includes(w));
}

function renderFindings() {
  const total = findings.length;
  findingsTab.replaceChildren("Findings", el("span", { class: "count", text: String(total) }));

  chips.replaceChildren();
  for (const sev of SEVERITIES) {
    const n = findings.filter((f) => f.severity === sev).length;
    if (!n) continue;
    const off = ui.severities.includes(sev);
    const chip = button("", `chip sev-${sev}${off ? " off" : ""}`, () => {
      ui.severities = off ? ui.severities.filter((s) => s !== sev) : [...ui.severities, sev];
      saveUi();
      renderFindings();
    }, `${off ? "Show" : "Hide"} ${sev} findings`);
    chip.setAttribute("aria-pressed", String(!off));
    chip.append(el("span", { class: "chip-dot" }), `${cap(sev)} `, el("strong", { text: String(n) }));
    chips.append(chip);
  }

  const shown = findings.filter((f) => !ui.severities.includes(f.severity) && matches(f, ui.query));
  const notes: string[] = [];
  if (shown.length !== total) notes.push(`Showing ${shown.length} of ${total}.`);
  if (hiddenFalsePositives && total) notes.push(`${hiddenFalsePositives} likely false alarms hidden (setting vulnScanner.showLikelyFalsePositives).`);
  findingsNote.textContent = notes.join(" ");
  findingsNote.classList.toggle("hidden", !notes.length);

  findingsList.replaceChildren();
  findingsEmpty.replaceChildren(total ? "No findings match the filter."
    : hiddenFalsePositives ? `No real problems found. ${hiddenFalsePositives} likely false alarm${hiddenFalsePositives === 1 ? " is" : "s are"} hidden. `
    : "No findings yet. Ask me to scan this project in the Chat tab.");
  if (!total && hiddenFalsePositives) {
    findingsEmpty.append(button("Show them", "link", () => send({ type: "showFalsePositives", on: true })));
  }
  findingsEmpty.classList.toggle("hidden", shown.length > 0);

  for (const sev of SEVERITIES) {
    const group = shown.filter((f) => f.severity === sev);
    if (!group.length) continue;
    const collapsed = ui.collapsed.includes(sev);
    const header = el("button", { class: `group-header sev-${sev}`, "aria-expanded": String(!collapsed) },
      el("span", { class: "chevron", text: collapsed ? "▸" : "▾" }), el("span", { class: "sev-dot" }),
      el("span", { class: "group-title", text: cap(sev) }), el("span", { class: "count", text: String(group.length) }));
    header.onclick = () => {
      ui.collapsed = collapsed ? ui.collapsed.filter((s) => s !== sev) : [...ui.collapsed, sev];
      saveUi();
      renderFindings();
    };
    const section = el("section", { class: "group" }, header);
    if (!collapsed) {
      let lastPath = "";
      for (const f of group) {
        if (f.path !== lastPath) {
          const { dir, name } = splitPath(f.path);
          const n = group.filter((x) => x.path === f.path).length;
          section.append(el("div", { class: "file-header", title: f.path },
            el("span", { class: "file-name", text: name }),
            // rtl clips long folders from the left; the inner ltr span keeps slashes in place
            el("span", { class: "file-dir" }, el("span", { dir: "ltr", text: dir.replace(/\/$/, "") })),
            el("span", { class: "count", text: String(n) })));
          lastPath = f.path;
        }
        section.append(renderFinding(f));
      }
    }
    findingsList.append(section);
  }
}

function isWorkspace() {
  return sessions.find((s) => s.session_id === current)?.target_type === "workspace";
}

/** Findings appear before the LLM has reviewed them; until then the explanation is empty. */
const pendingReview = (f: FindingView) => !f.explanation && !f.fix_recommendation;

function renderFinding(f: FindingView) {
  const v = pendingReview(f) ? { label: "Reviewing…", cls: "pending" }
    : VERDICT[f.verdict] ?? { label: f.verdict, cls: "unsure" };
  const isOpen = expanded.has(f.id);
  const row = el("div", { class: `finding sev-${f.severity}${isOpen ? " open" : ""}`, "data-id": f.id });

  const head = el("button", { class: "finding-head", "aria-expanded": String(isOpen), title: f.title },
    el("span", { class: `badge sev-${f.severity}`, text: BADGE[f.severity] ?? f.severity.toUpperCase() }),
    el("span", { class: "finding-main" },
      el("span", { class: "finding-title", text: f.title }),
      el("span", { class: "finding-meta" },
        el("span", { class: "loc", text: `${splitPath(f.path).name}:${f.start_line}` }),
        el("span", { class: `verdict ${v.cls}`, text: v.label }),
        el("span", { class: "tools", text: f.tools.join(" + ") }),
        ...(f.status === "new" ? [el("span", { class: "new", text: "NEW" })] : []),
        ...(f.outdated ? [el("span", { class: "outdated", text: "file changed", title: "This file changed since the scan" })] : []))));
  head.onclick = () => {
    if (expanded.has(f.id)) expanded.delete(f.id);
    else expanded.add(f.id);
    renderFindings();
  };
  row.append(head);
  if (isOpen) row.append(renderDetails(f));
  return row;
}

function renderDetails(f: FindingView) {
  const card = el("div", { class: "details" });
  if (f.outdated) {
    card.append(el("div", { class: "callout warn",
      text: "This file changed since the scan. The line may have moved. Click Rescan to update." }));
  }
  const section = (label: string, text: string) => {
    if (!text) return;
    const body = el("div", { class: "body" });
    body.innerHTML = md.render(text);
    card.append(el("div", { class: "label", text: label }), body);
  };
  if (pendingReview(f)) {
    card.append(el("div", { class: "callout", text: "The LLM is still reviewing this finding. The scanner says:" }));
    section("Scanner message", f.message);
  } else {
    section("What's wrong", f.explanation || f.message);
    section("How to fix", f.fix_recommendation);
  }
  if (f.suggested_patch) {
    card.append(el("div", { class: "label", text: "Suggested patch" }),
      el("pre", { class: "patch" }, el("code", { text: f.suggested_patch })));
  }
  const actions = el("div", { class: "detail-actions" },
    button("Open", "", () => send({ type: "openFinding", id: f.id }), f.web_url ? "Open on GitHub" : "Open in the editor"));
  if (isWorkspace() && !pendingReview(f)) {
    actions.append(button("Fix", "secondary", () => {
      setTab("chat");
      send({ type: "fix", ids: [f.id] });
    }, "Let the assistant fix this in your code. You see the change before it is applied."));
  }
  if (f.suggested_patch) actions.append(copyButton(() => f.suggested_patch ?? "", "secondary", "Copy patch"));
  actions.append(button("Ask in chat", "secondary", () => {
    setTab("chat");
    send({ type: "send", text: `Explain finding \`${f.id}\` (${f.title} in ${f.path}:${f.start_line}) and how to fix it.` });
  }));
  card.append(actions);
  card.append(el("div", { class: "facts" },
    el("span", { text: f.path, title: "File" }),
    el("span", { text: `Lines ${f.start_line}${f.end_line !== f.start_line ? `–${f.end_line}` : ""}` }),
    el("span", { text: f.rule_id, title: "Rule" }),
    ...(f.cwe ? [el("span", { text: f.cwe })] : [])));
  return card;
}

// --- events ---

function submit() {
  const text = input.value.trim();
  if (!text || sendBtn.disabled) return;
  input.value = "";
  send({ type: "send", text });
}

sendBtn.onclick = submit;
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
    e.preventDefault();
    submit();
  }
});
search.value = ui.query;
search.addEventListener("input", () => {
  ui.query = search.value.trim();
  saveUi();
  renderFindings();
});
chatTab.onclick = () => setTab("chat");
findingsTab.onclick = () => setTab("findings");
stopBtn.onclick = () => send({ type: "cancel" });
rescanBtn.onclick = () => {
  setTab("chat");
  send({ type: "runCommand", command: "vulnScanner.rescan" });
};
fixAllBtn.onclick = () => {
  setTab("chat");
  send({ type: "send", text: "Fix all findings" });
};
summarizeBtn.onclick = () => {
  setTab("chat");
  send({ type: "send", text: "Summarize all findings" });
};
newBtn.onclick = () => send({ type: "newSession" });
deleteBtn.onclick = () => current && send({ type: "deleteSession", id: current });
sessionSelect.onchange = () => sessionSelect.value && send({ type: "switchSession", id: sessionSelect.value });
renameBtn.onclick = () => {
  const s = sessions.find((x) => x.session_id === current);
  if (!s) return;
  renameInput.value = s.name;
  sessionSelect.classList.add("hidden");
  renameInput.classList.remove("hidden");
  renameInput.focus();
  renameInput.select();
};
function endRename(save: boolean) {
  if (renameInput.classList.contains("hidden")) return;
  if (save && current && renameInput.value.trim()) send({ type: "renameSession", id: current, name: renameInput.value.trim() });
  renameInput.classList.add("hidden");
  sessionSelect.classList.remove("hidden");
}
renameInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") endRename(true);
  if (e.key === "Escape") endRename(false);
});
renameInput.addEventListener("blur", () => endRename(true));

window.addEventListener("message", (event: MessageEvent<ToWebview>) => {
  const msg = event.data;
  switch (msg.type) {
    case "state":
      setStatus(msg.connection);
      sessions = msg.sessions;
      if (msg.current !== current) {
        messages.replaceChildren();
        updateWelcome();
        findings = [];
        expanded.clear();
        renderFindings();
      }
      current = msg.current;
      scanning = msg.scanning;
      changedFiles = msg.changed;
      renderSessions();
      updateControls();
      break;
    case "history":
      messages.replaceChildren();
      msg.messages.forEach(renderMessage);
      updateWelcome();
      break;
    case "confirm":
      renderConfirm(msg.id, msg.yes, msg.no);
      break;
    case "confirmDone":
      confirmRows.get(msg.id)?.remove();
      confirmRows.delete(msg.id);
      break;
    case "message":
      renderMessage(msg.message);
      break;
    case "summaryCard":
      renderSummaryCard(msg.card, msg.hidden, msg.error);
      break;
    case "agentStart":
      agentStart(msg.id, msg.title);
      break;
    case "agentEvent":
      agentEvent(msg.id, msg.event);
      break;
    case "agentEnd":
      agentEnd(msg.id, msg.title);
      break;
    case "thinking":
      thinking.classList.toggle("hidden", !msg.on);
      if (msg.on) messages.scrollTop = messages.scrollHeight;
      break;
    case "progress":
      progress.classList.toggle("hidden", !!msg.done);
      progressBar.style.width = `${Math.max(0, Math.min(100, msg.percent))}%`;
      progressText.textContent = `${msg.percent}% · ${msg.message}`;
      break;
    case "findings": {
      const wasEmpty = findings.length === 0;
      findings = msg.findings;
      hiddenFalsePositives = msg.hidden;
      renderFindings();
      updateControls();
      // A finished scan brings new findings: show them.
      if (wasEmpty && findings.length && scanning) setTab("findings");
      break;
    }
    case "error":
      showError(msg.message, msg.action);
      break;
  }
});

setTab(ui.tab);
updateWelcome();
renderFindings();
updateControls();
send({ type: "ready" });
