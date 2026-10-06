import assert from "node:assert/strict";
import { test } from "node:test";
import { applyEdits, diagnosticLevel, diagnosticMessage, firstSentence, mergeEdits, parseAgentEvent, scanSummaryText, sortFindings, splitHidden }
  from "../../src/findingsLogic";

const f = (o: any) => ({ id: "x", tools: [], rule_id: "", title: "T", severity: "low", cwe: null, path: "a",
  start_line: 1, end_line: 1, start_col: null, end_col: null, file_sha256: "", message: "", snippet: "",
  verdict: "likely_real", explanation: "", fix_recommendation: "", suggested_patch: null, status: "new",
  web_url: null, ...o });

test("sort by severity, then file, then line", () => {
  const out = sortFindings([f({ id: "1", severity: "low" }), f({ id: "2", severity: "critical", path: "b" }),
    f({ id: "3", severity: "critical", path: "a", start_line: 9 }), f({ id: "4", severity: "critical", path: "a" })]);
  assert.deepEqual(out.map((x) => x.id), ["4", "3", "2", "1"]);
});

test("likely false positives are hidden unless asked for", () => {
  const list = [f({}), f({ verdict: "likely_false_positive" }), f({ verdict: "unsure" })];
  assert.deepEqual([splitHidden(list, false).shown.length, splitHidden(list, false).hidden], [2, 1]);
  assert.equal(splitHidden(list, true).hidden, 0);
});

test("diagnostics", () => {
  assert.equal(diagnosticLevel("critical"), "error");
  assert.equal(diagnosticLevel("high"), "error");
  assert.equal(diagnosticLevel("medium"), "warning");
  assert.equal(diagnosticLevel("low"), "information");
  assert.equal(diagnosticLevel("info"), "information");
  assert.equal(firstSentence("Use a parameterised query. Then test it."), "Use a parameterised query.");
  assert.equal(firstSentence("No period"), "No period");
  assert.equal(firstSentence("Call v1.2 of the API. Done."), "Call v1.2 of the API.");
  assert.equal(diagnosticMessage(f({ title: "SQL injection", fix_recommendation: "Bind params. More." })),
    "SQL injection: Bind params.");
});

test("summary text", () => {
  assert.match(scanSummaryText({ high: 2, low: 1 }, 1, null), /3 findings.*2 high, 1 low.*1 new/);
  assert.match(scanSummaryText({}, 0, "sonarqube: down"), /no findings[\s\S]*sonarqube: down/);
  assert.match(scanSummaryText({ medium: 1, low: 1 }, 2, null, 2), /All of them look like false alarms, so they are hidden/);
  assert.match(scanSummaryText({ high: 3 }, 0, null, 1), /1 of them look like false alarms, so it is hidden/);
});

test("fix edits replace whole lines and keep line endings", () => {
  const text = "a\r\nb\r\nc\r\nd\r\n";
  assert.equal(applyEdits(text, [{ start_line: 2, end_line: 2, replacement: "B1\nB2" },
                                 { start_line: 4, end_line: 4, replacement: "" }]), "a\r\nB1\r\nB2\r\nc\r\n");
  assert.equal(applyEdits("x\ny", [{ start_line: 1, end_line: 2, replacement: "z" }]), "z");
  assert.throws(() => applyEdits("x", [{ start_line: 2, end_line: 3, replacement: "" }]), /outside the file/);
});

test("overlapping fix edits keep the first", () => {
  const { kept, dropped } = mergeEdits([{ start_line: 5, end_line: 6, replacement: "b" },
                                        { start_line: 1, end_line: 5, replacement: "a" },
                                        { start_line: 8, end_line: 8, replacement: "c" }]);
  assert.deepEqual(kept.map((e) => e.replacement), ["a", "c"]);
  assert.deepEqual(dropped.map((e) => e.replacement), ["b"]);
});

test("fix agent progress messages are events; plain text becomes a status line", () => {
  assert.deepEqual(parseAgentEvent('{"file": "db.py", "kind": "tool", "text": "Read db.py"}'),
                   { file: "db.py", kind: "tool", text: "Read db.py" });
  assert.deepEqual(parseAgentEvent("db.py: editing"), { file: null, kind: "status", text: "db.py: editing" });
  assert.deepEqual(parseAgentEvent('{"oops": 1}'), { file: null, kind: "status", text: '{"oops": 1}' });
});
