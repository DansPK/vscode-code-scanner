import assert from "node:assert/strict";
import { createHash } from "crypto";
import { promises as fs } from "fs";
import { test } from "node:test";
import { createArchive, largestFolders, listArchive, removeArchive } from "../../src/archive";
import { makeTree } from "./helpers";

test("archive holds exactly the needed files at their relative paths", async () => {
  const root = await makeTree({ "a.js": "a", "src/b.js": "b", "src/c.js": "c" });
  const arc = await createArchive(root, ["src/b.js", "a.js"]);
  try {
    assert.deepEqual((await listArchive(arc.file)).sort(), ["a.js", "src/b.js"]);
    const data = await fs.readFile(arc.file);
    assert.equal(arc.size, data.length);
    assert.equal(arc.sha256, createHash("sha256").update(data).digest("hex"));
  } finally {
    await removeArchive(arc);
  }
  await assert.rejects(fs.stat(arc.file));
});

test("largest folders", () => {
  const e = (path: string, size: number) => ({ path, size, sha256: "" });
  assert.deepEqual(largestFolders([e("a.js", 5), e("src/x/y.js", 50), e("src/x/z.js", 50), e("lib/q.js", 70),
    e("src/w.js", 1)]), [
    { folder: "src/x/", bytes: 100 }, { folder: "lib/", bytes: 70 }, { folder: "(root files)", bytes: 5 },
    { folder: "src/", bytes: 1 }]);
});
