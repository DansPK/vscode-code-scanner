import assert from "node:assert/strict";
import { createHash } from "crypto";
import { promises as fs } from "fs";
import * as path from "path";
import { test } from "node:test";
import { walkWorkspace } from "../../src/workspaceFiles";
import { makeTree } from "./helpers";

test("walk applies skip list, gitignore files, excludes, binary and size limits", async () => {
  const root = await makeTree({
    "app.js": "console.log(1)\n",
    "src/lib/util.ts": "export const x = 1;\n",
    "src/lib/secret.env": "KEY=1\n",
    "src/.gitignore": "*.env\ngenerated/\n",
    "src/generated/big.ts": "x\n",
    ".gitignore": "logs/\n/only-root.txt\n",
    "logs/a.log": "x\n",
    "only-root.txt": "x\n",
    "sub/only-root.txt": "kept, the rule is anchored to the root\n",
    "node_modules/pkg/index.js": "x\n",
    "deep/node_modules/pkg/index.js": "x\n",
    ".git/config": "x\n",
    "dist/out.js": "x\n",
    ".vscode/settings.json": "{}\n",
    "image.png": Buffer.from([0x89, 0x50, 0x00, 0x01]),
    "large.txt": "a".repeat(3 * 1024),
    "docs/notes.md": "# notes\n",
    "docs/draft.md": "draft\n",
  });
  await fs.symlink(path.join(root, "app.js"), path.join(root, "link.js"));
  await fs.symlink(path.join(root, "src"), path.join(root, "srclink"));

  const { entries, skipped } = await walkWorkspace(root, { maxFileSizeKB: 2, extraExcludes: ["docs/draft.md"] });
  const paths = entries.map((e) => e.path).sort();
  assert.deepEqual(paths, [".gitignore", "app.js", "docs/notes.md", "src/.gitignore", "src/lib/util.ts",
    "sub/only-root.txt"]);
  assert.deepEqual(skipped, { binary: 1, large: 1 });
  const app = entries.find((e) => e.path === "app.js")!;
  assert.equal(app.size, 15);
  assert.equal(app.sha256, createHash("sha256").update("console.log(1)\n").digest("hex"));
  assert.ok(entries.every((e) => !e.path.includes("\\") && !e.path.startsWith("/")));
});

test("walk can be cancelled", async () => {
  const root = await makeTree({ "a.txt": "a", "b/c.txt": "c" });
  await assert.rejects(walkWorkspace(root, { maxFileSizeKB: 10, extraExcludes: [], isCancelled: () => true }),
    /Cancelled/);
});
