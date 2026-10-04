// Downloads VS Code (cached in .vscode-test) and runs the integration suite inside it.

import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import { runTests } from "@vscode/test-electron";

async function main() {
  // When run from a VS Code terminal, this is set and would start VS Code as plain Node.
  delete process.env.ELECTRON_RUN_AS_NODE;
  const root = path.resolve(__dirname, "../../..");
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "vs-int-"));
  const files: Record<string, string> = {
    "app.js": "const a = 1;\nconst q = 'SELECT * FROM t WHERE id=' + id;\ndb.query(q);\n",
    "lib/util.js": "module.exports = {};\n",
    "node_modules/x/index.js": "skipped\n",
  };
  for (const [rel, text] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(workspace, rel)), { recursive: true });
    await fs.writeFile(path.join(workspace, rel), text);
  }
  const userData = await fs.mkdtemp(path.join(os.tmpdir(), "vs-user-"));
  await runTests({
    extensionDevelopmentPath: root,
    extensionTestsPath: path.join(__dirname, "suite"),
    launchArgs: [workspace, "--disable-extensions", "--disable-workspace-trust", `--user-data-dir=${userData}`],
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
