// Integration tests, run inside VS Code against the fake harness.

import assert from "node:assert/strict";
import { promises as fs } from "fs";
import * as path from "path";
import * as vscode from "vscode";
import type { Controller } from "../../src/controller";
import type { ToWebview } from "../../src/shared/messages";
import { FakeHarness } from "../fakeServer";

const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);

let fake: FakeHarness;
let controller: Controller;
let context: vscode.ExtensionContext;
let posted: ToWebview[] = [];
let latestState: Extract<ToWebview, { type: "state" }> | undefined; // kept when `posted` is cleared
const root = () => vscode.workspace.workspaceFolders![0].uri.fsPath;

const last = <T extends ToWebview["type"]>(type: T) =>
  (type === "state" ? latestState : [...posted].reverse().find((m) => m.type === type)) as
    Extract<ToWebview, { type: T }> | undefined;
const texts = () => posted.filter((m) => m.type === "message").map((m: any) => m.message.text as string);

test("the extension activates and the chat panel opens", async () => {
  const ext = vscode.extensions.getExtension("local.vuln-scanner")!;
  const api = await ext.activate();
  controller = api.controller;
  context = api.context;
  controller.attach({ post: (m) => {
    posted.push(m);
    if (m.type === "state") latestState = m;
  } });
  await vscode.commands.executeCommand("vulnScanner.openChat");
});

test("no server URL or token: a short message with the right button", async () => {
  await controller.connect();
  const s = last("state")!;
  assert.equal(s.connection.state, "disconnected");
  assert.equal((s.connection as any).action.command, "vulnScanner.openSettings");
});

test("a bad token shows the 401 message; a good one connects", async () => {
  console.log("    updating setting");
  await vscode.workspace.getConfiguration("vulnScanner").update("serverUrl", fake.url,
    vscode.ConfigurationTarget.Workspace);
  console.log("    setting bad token");
  await controller.setToken("bad-token-xyz");
  console.log("    bad token done");
  assert.equal((last("state")!.connection as any).reason, "Token rejected. Run Vuln Scanner: Set Token.");
  await controller.setToken(fake.token);
  assert.equal(last("state")!.connection.state, "connected");
});

test("scan this project: progress, summary, findings, Problems panel, open at line", async () => {
  posted = [];
  fake.stepMs = 400; // slow enough to see findings arrive while the scan runs
  await controller.send("scan this project");
  fake.stepMs = 30;
  const liveLists = posted.filter((m) => m.type === "findings") as Extract<ToWebview, { type: "findings" }>[];
  assert.ok(liveLists.some((m) => m.findings.some((f) => f.explanation === "")),
    "findings were shown before their review finished");
  assert.ok(posted.some((m) => m.type === "progress" && !m.done), "progress lines");
  assert.ok(texts().some((t) => t.startsWith("**2 findings.** Fix the SQL injection first.")
    && /1 likely false alarm is hidden/.test(t)), "short summary shown by itself after the scan");
  assert.ok(texts().some((t) => /sonarqube/.test(t)), "failed scanner is named");
  const f = last("findings")!;
  assert.equal(f.total, 2);
  assert.equal(f.hidden, 1);
  assert.deepEqual(f.findings.map((x) => x.path), ["app.js"]);
  const archive = fake.calls.find((c) => c.name === "sync_files")!.args.manifest.map((e: any) => e.path).sort();
  assert.deepEqual(archive, ["app.js", "lib/util.js"]);

  const diags = controller.getDiagnostics();
  assert.equal(diags.length, 1);
  assert.equal(path.basename(diags[0][0].fsPath), "app.js");
  assert.equal(diags[0][1][0].severity, vscode.DiagnosticSeverity.Error);
  assert.equal(diags[0][1][0].message, "SQL injection: Use a parameterised query.");
  const fromProblems = vscode.languages.getDiagnostics(diags[0][0]).filter((d) => d.source === "Vuln Scanner");
  assert.equal(fromProblems.length, 1);

  await controller.openFinding(f.findings[0].id);
  const ed = vscode.window.activeTextEditor!;
  assert.equal(path.basename(ed.document.uri.fsPath), "app.js");
  assert.equal(ed.selection.start.line, 1);
  assert.equal(ed.selection.end.line, 2);
});

test("editing a file marks its findings out of date; rescan uploads only that file", async () => {
  await fs.writeFile(path.join(root(), "app.js"), "const a = 2;\nconst q = 'x';\ndb.query(q);\n");
  await controller.loadFindings();
  assert.equal(last("findings")!.findings[0].outdated, true);
  posted = [];
  await controller.send("rescan");
  const names = await archiveNames(fake.lastUploadArchive()!);
  assert.deepEqual(names, ["app.js"]);
  assert.ok(texts().some((t) => /Uploaded 1 changed file/.test(t)));
  posted = [];
  await controller.send("scan again");
  assert.ok(texts().includes("No files changed since the last scan."));
});

test("the agent asks first when unsure; Yes runs the scan, No does not", async () => {
  posted = [];
  await controller.send("is my code safe?");
  const ask = last("confirm")!;
  assert.ok(ask, "Yes/No buttons were shown");
  assert.ok(texts().includes("Do you want me to scan the workspace?"));
  const scansBefore = fake.calls.filter((c) => c.name === "start_scan").length;
  await controller.handle({ type: "confirm", id: ask.id, accept: false });
  assert.ok(texts().includes("OK, I won't."));
  assert.equal(fake.calls.filter((c) => c.name === "start_scan").length, scansBefore);

  posted = [];
  await controller.send("is my code safe?");
  await controller.handle({ type: "confirm", id: last("confirm")!.id, accept: true });
  // Nothing changed since the last scan, so the extension says so instead of scanning.
  assert.ok(texts().includes("No files changed since the last scan."));
});

test("full and folder scans are passed on to the harness", async () => {
  posted = [];
  await controller.send("scan everything again from scratch");
  let call = fake.calls.filter((c) => c.name === "start_scan").pop()!;
  assert.equal(call.args.full, true);
  await controller.send("scan only the lib folder");
  call = fake.calls.filter((c) => c.name === "start_scan").pop()!;
  assert.deepEqual(call.args.paths, ["lib"]);
});

test("when the LLM is down, scan commands still work by keyword", async () => {
  fake.llmDown = true;
  try {
    posted = [];
    const before = fake.calls.filter((c) => c.name === "sync_files").length;
    await controller.send("rescan");
    assert.ok(texts().some((t) => t.startsWith("The assistant is unavailable right now")));
    assert.ok(fake.calls.filter((c) => c.name === "sync_files").length > before, "the workspace was synced");
    posted = [];
    await assert.rejects(controller.send("what is XSS?"), /LLM cannot be reached/);
  } finally {
    fake.llmDown = false;
  }
});

test("saving a file with findings lights up the Rescan button, without chat messages", async () => {
  posted = [];
  const uri = vscode.Uri.file(path.join(root(), "app.js"));
  controller.onSaved(uri);
  controller.onSaved(uri); // the same file counts once
  controller.onSaved(vscode.Uri.file(path.join(root(), "no-findings.txt")));
  assert.equal(last("state")!.changed, 1);
  assert.equal(texts().length, 0);
  assert.ok(!last("confirm"));
});

test("chat goes to the chat tool and comes back as Markdown text", async () => {
  posted = [];
  await controller.send("what is the worst finding?");
  assert.ok(texts().some((t) => t.startsWith("You said: **what is the worst finding?**")));
  assert.ok(posted.some((m) => m.type === "thinking" && m.on));
});

const waitFor = async (what: string, ok: () => boolean) => {
  for (let i = 0; i < 100 && !ok(); i++) await new Promise((r) => setTimeout(r, 50));
  assert.ok(ok(), what);
};
const confirmWith = (yes: string) => posted.filter((m) => m.type === "confirm" && m.yes === yes).pop() as
  Extract<ToWebview, { type: "confirm" }> | undefined;

test("fix: the change is shown first, written only on Apply, and never to a changed file", async () => {
  const app = path.join(root(), "app.js");
  const util = path.join(root(), "lib", "util.js");
  const utilBefore = await fs.readFile(util, "utf8");
  posted = [];
  await controller.handle({ type: "fix", ids: ["f1"] });
  await waitFor("util.js diff is offered", () => texts().some((t) => t.startsWith("Proposed fix for `lib/util.js`")));
  // The live transcript: a block, the agent's events streamed into it (no heartbeats), then its end.
  const live = posted.filter((m) => m.type.startsWith("agent")) as any[];
  assert.equal(live[0].type, "agentStart");
  assert.deepEqual(live.filter((m) => m.type === "agentEvent").map((m) => m.event.kind),
                   ["start", "thinking", "thinking", "tool", "result", "text", "done"]);
  assert.match(live[live.length - 1].title, /^Fix agent finished in \d+ s$/);
  assert.ok(vscode.window.tabGroups.activeTabGroup.activeTab?.label.includes("proposed fix"), "the diff is open");
  await controller.handle({ type: "confirm", id: confirmWith("Apply fix")!.id, accept: false });
  assert.equal(await fs.readFile(util, "utf8"), utilBefore, "Skip leaves the file alone");

  // Several files: review one by one, in path order
  posted = [];
  await controller.send("fix all of them"); // the agent returns a fix action for both findings
  assert.ok(texts().some((t) => t.startsWith("**Fix agent:** 2 fixed and confirmed by the scanners.")));
  const choice = confirmWith("Apply all (2 files)");
  assert.ok(choice, "apply all or review");
  await controller.handle({ type: "confirm", id: choice!.id, accept: false });
  await waitFor("app.js diff is offered", () => texts().some((t) => t.startsWith("Proposed fix for `app.js` (file 1 of 2)")));
  assert.equal(await fs.readFile(app, "utf8"), "const a = 2;\nconst q = 'x';\ndb.query(q);\n", "nothing written yet");
  await controller.handle({ type: "confirm", id: confirmWith("Apply fix")!.id, accept: true });
  assert.equal(await fs.readFile(app, "utf8"), "const a = 2;\n// fixed\n");
  await waitFor("util.js is next", () => texts().some((t) => t.startsWith("Proposed fix for `lib/util.js` (file 2 of 2)")));
  await controller.handle({ type: "confirm", id: confirmWith("Apply fix")!.id, accept: false });
  assert.ok(texts().includes("Skipped `lib/util.js`."));
  assert.equal(await fs.readFile(util, "utf8"), utilBefore);

  // Apply all: app.js changed since the upload, so only util.js is written
  posted = [];
  await controller.send("fix all of them");
  await controller.handle({ type: "confirm", id: confirmWith("Apply all (2 files)")!.id, accept: true });
  assert.ok(texts().some((t) => t.startsWith("Applied changes to 1 of 2 files.")
    && /`app.js` changed since it was last uploaded/.test(t)));
  assert.ok((await fs.readFile(util, "utf8")).startsWith("// fixed"));
  assert.equal(await fs.readFile(app, "utf8"), "const a = 2;\n// fixed\n");
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
});

test("sessions: new, rename, switch back with history, remembered after a restart", async () => {
  const first = last("state")!.current!;
  await controller.newSession();
  const second = last("state")!.current!;
  assert.notEqual(first, second);
  await controller.renameSession(second, "Renamed");
  assert.ok(last("state")!.sessions.some((s) => s.session_id === second && s.name === "Renamed"));
  posted = [];
  await controller.switchSession(first);
  const hist = last("history")!;
  assert.ok(hist.messages.some((m) => m.text === "what is the worst finding?"));

  // A fresh controller with the same workspace state stands in for a VS Code restart.
  const restarted: ToWebview[] = [];
  const Ctl = Object.getPrototypeOf(controller).constructor as new (c: vscode.ExtensionContext) => Controller;
  const again = new Ctl(context);
  again.attach({ post: (m) => restarted.push(m) });
  await again.connect();
  const state = [...restarted].reverse().find((m) => m.type === "state") as any;
  assert.equal(state.current, first);
  assert.ok(restarted.some((m) => m.type === "history" && m.messages.some((x) => x.text === "what is the worst finding?")));
  again.dispose();
});

test("delete asks first", async () => {
  const win = vscode.window as any;
  const orig = win.showWarningMessage;
  const target = last("state")!.sessions.find((s) => s.name === "Renamed")!.session_id;
  try {
    win.showWarningMessage = async () => undefined; // user says no
    await controller.deleteSession(target);
    assert.ok(fake.sessions.has(target));
    win.showWarningMessage = async () => "Delete";
    await controller.deleteSession(target);
    assert.ok(!fake.sessions.has(target));
  } finally {
    win.showWarningMessage = orig;
  }
});

test("a GitHub link scans the repo and findings open in the browser", async () => {
  const env = vscode.env as any;
  const orig = env.openExternal;
  let opened = "";
  try {
    env.openExternal = async (u: vscode.Uri) => { opened = u.toString(true); return true; };
    posted = [];
    await controller.send("check https://github.com/acme/app");
    const s = last("state")!;
    assert.equal(s.sessions.find((x) => x.session_id === s.current)!.target_type, "github");
    const f = last("findings")!.findings[0];
    await controller.openFinding(f.id);
    assert.equal(opened, "https://github.com/acme/app/blob/abc/app.js#L2-L3");
  } finally {
    env.openExternal = orig;
  }
});

test("a token pasted into the settings moves to secret storage", async () => {
  const c = vscode.workspace.getConfiguration("vulnScanner");
  await context.secrets.delete("vulnScanner.token");
  await c.update("token", fake.token, vscode.ConfigurationTarget.Workspace);
  await controller.connect();
  assert.equal(await context.secrets.get("vulnScanner.token"), fake.token);
  assert.equal(vscode.workspace.getConfiguration("vulnScanner").inspect("token")?.workspaceValue, undefined);
  // Changing the setting also starts a reconnect of its own; wait for whichever finishes last.
  await waitFor("connected", () => latestState?.connection.state === "connected");
});

test("the token never reaches settings, logs or the webview", async () => {
  const settings = await fs.readFile(path.join(root(), ".vscode", "settings.json"), "utf8");
  assert.ok(!settings.includes(fake.token));
  assert.ok(!JSON.stringify(posted).includes(fake.token));
  assert.equal(await context.secrets.get("vulnScanner.token"), fake.token);
});

async function archiveNames(data: Buffer) {
  const tar = await import("tar");
  const os = await import("os");
  const file = path.join(await fs.mkdtemp(path.join(os.tmpdir(), "arc-")), "a.tar.gz");
  await fs.writeFile(file, data);
  const names: string[] = [];
  await tar.list({ file, onReadEntry: (e: any) => { names.push(e.path); } });
  return names.sort();
}

const LOG = process.env.VS_TEST_LOG;
const note = (t: string) => { if (LOG) require("fs").appendFileSync(LOG, t + "\n"); };
process.on("uncaughtException", (e) => note(`uncaughtException: ${e.stack}`));
process.on("unhandledRejection", (e: any) => note(`unhandledRejection: ${e?.stack ?? e}`));
process.on("exit", (c) => note(`exit ${c}`));

const TEST_TIMEOUT_MS = 60_000;

export async function run() {
  fake = new FakeHarness({ stepMs: 30, findings: [
    { path: "app.js", start_line: 2, end_line: 3, severity: "high", title: "SQL injection",
      fix_recommendation: "Use a parameterised query. Bind the id." },
    { path: "lib/util.js", severity: "medium", verdict: "likely_false_positive" },
  ] });
  await fake.start();
  let failed = 0;
  try {
    for (const [name, fn] of tests) {
      try {
        console.log(`  ...   ${name}`);
        // A hung test fails instead of keeping the test window open forever.
        let timer: NodeJS.Timeout | undefined;
        await Promise.race([fn(), new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`timed out after ${TEST_TIMEOUT_MS / 1000} s`)), TEST_TIMEOUT_MS);
        })]).finally(() => clearTimeout(timer));
        console.log(`  ok    ${name}`);
        note(`ok ${name}`);
      } catch (e) {
        failed++;
        console.log(`  FAIL  ${name}\n${(e as Error).stack}`);
        note(`FAIL ${name}\n${(e as Error).stack}`);
      }
    }
  } finally {
    await fake.stop();
  }
  if (failed) throw new Error(`${failed} integration tests failed`);
}
