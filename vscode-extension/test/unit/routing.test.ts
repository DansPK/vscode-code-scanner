import assert from "node:assert/strict";
import { test } from "node:test";
import { route } from "../../src/routing";

const cases: [string, string][] = [
  ["scan https://github.com/acme/app please", "github"],
  ["check https://github.com/acme/app.git", "github"],
  ["rescan https://github.com/acme/app", "github"], // a link wins over rescan
  ["rescan", "rescan"],
  ["please rescan now", "rescan"],
  ["can you scan again?", "rescan"],
  ["scan this project", "scan"],
  ["Analyze the workspace", "scan"],
  ["analyse my code", "scan"],
  ["check this folder for problems", "scan"],
  ["scan", "chat"], // a verb alone is not enough
  ["what is SQL injection?", "chat"],
  ["explain finding abc123", "chat"],
  ["is this code safe?", "chat"],
  ["the scanner missed a bug in my project", "chat"],
  ["https://gitlab.com/acme/app", "chat"],
];

for (const [text, kind] of cases) {
  test(`route: ${text}`, () => assert.equal(route(text).kind, kind));
}

test("route extracts a clean GitHub URL", () => {
  assert.deepEqual(route("look at https://github.com/acme/my-app.git, thanks"),
    { kind: "github", url: "https://github.com/acme/my-app" });
  assert.deepEqual(route("(https://github.com/acme/app)."), { kind: "github", url: "https://github.com/acme/app" });
});
