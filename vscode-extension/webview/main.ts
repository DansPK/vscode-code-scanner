// The chat panel UI. It talks only to the extension, through postMessage.

import MarkdownIt from "markdown-it";
import type { ChatMessage, SessionInfo } from "../src/shared/contract";
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

const scanBtn = el("button", { text: "Scan" });
const rescanBtn = el("button", { class: "secondary", text: "Rescan" });
const cancelBtn = el("button", { class: "secondary", text: "Cancel" });
const scanBar = el("div", { class: "scanbar" }, scanBtn, rescanBtn, cancelBtn);

const progress = el("div", { class: "progress hidden" });
const progressBar = el("div", { class: "bar" });
const progressText = el("div", { class: "progress-text" });
progress.append(el("div", { class: "track" }, progressBar), progressText);

const chatTab = el("button", { class: "tab", role: "tab", text: "Chat" });
const findingsTab = el("button", { class: "tab", role: "tab" });
const tabs = el("div", { class: "tabs", role: "tablist" }, chatTab, findingsTab);

// chat panel
const messages = el("div", { class: "messages", role: "log", "aria-live": "polite" });
const thinking = el("div", { class: "thinking hidden", text: "Thinking..." });
const input = el("textarea", { rows: "2", placeholder: "Ask a question, or type \"scan this project\" or a GitHub link",
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
const findingsPanel = el("div", { class: "panel findings-panel" },
  el("div", { class: "filters" }, chips, search), findingsNote, findingsList, findingsEmpty);

document.getElementById("app")!.append(status, sessionBar, scanBar, progress, tabs, chatPanel, findingsPanel);

// --- state ---

let sessions: SessionInfo[] = [];
let current: string | null = null;
let scanning = false;
let busy = false;
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
  const can = connected && !scanning && !busy;
  scanBtn.disabled = !can;
  rescanBtn.disabled = !can;
  cancelBtn.disabled = !scanning;
  cancelBtn.classList.toggle("hidden", !scanning);
  sendBtn.disabled = !connected;
  newBtn.disabled = !connected;
  renameBtn.disabled = !connected || !current;
  deleteBtn.disabled = !connected || !current;
  sessionSelect.disabled = !connected || scanning;
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
  messages.scrollTop = messages.scrollHeight;
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
  if (hiddenFalsePositives) notes.push(`${hiddenFalsePositives} likely false alarms hidden (setting vulnScanner.showLikelyFalsePositives).`);
  findingsNote.textContent = notes.join(" ");
  findingsNote.classList.toggle("hidden", !notes.length);

  findingsList.replaceChildren();
  findingsEmpty.textContent = total ? "No findings match the filter." : "No findings yet. Click Scan to scan this project.";
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

/** Findings appear before the LLM has reviewed them; until then the explanation is empty. */
const pendingReview = (f: FindingView) => !f.explanation && !f.fix_recommendation;

function renderFinding(f: FindingView) {
  const v = pendingReview(f) ? { label: "Reviewing…", cls: "pending" }
    : VERDICT[f.verdict] ?? { label: f.verdict, cls: "unsure" };
  const isOpen = expanded.has(f.id);
  const row = el("div", { class: `finding sev-${f.severity}${isOpen ? " open" : ""}` });

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
scanBtn.onclick = () => send({ type: "scan" });
rescanBtn.onclick = () => send({ type: "rescan" });
cancelBtn.onclick = () => send({ type: "cancel" });
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
        findings = [];
        expanded.clear();
        renderFindings();
      }
      current = msg.current;
      scanning = msg.scanning;
      busy = msg.busy;
      renderSessions();
      updateControls();
      break;
    case "history":
      messages.replaceChildren();
      msg.messages.forEach(renderMessage);
      break;
    case "message":
      renderMessage(msg.message);
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
renderFindings();
updateControls();
send({ type: "ready" });
