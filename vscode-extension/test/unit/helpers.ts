import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";

export async function makeTree(files: Record<string, string | Buffer>): Promise<string> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "vs-test-"));
  for (const [rel, data] of Object.entries(files)) {
    const full = path.join(root, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, data);
  }
  return root;
}
