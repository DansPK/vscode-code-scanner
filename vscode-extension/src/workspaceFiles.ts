// Walk a workspace folder and build the manifest: relative path, SHA-256 and size per file.

import { createHash } from "crypto";
import { createReadStream, promises as fs } from "fs";
import * as path from "path";
import ignore, { Ignore } from "ignore";
import type { ManifestEntry } from "./shared/contract";

export const SKIP_FOLDERS = new Set([".git", "node_modules", "build", "dist", "out", "target", "bin", "obj",
  ".venv", "venv", "__pycache__", ".idea", ".vscode"]);
const BINARY_SNIFF_BYTES = 8192;

export interface WalkOptions {
  maxFileSizeKB: number;
  extraExcludes: string[];
  isCancelled?: () => boolean;
  onProgress?: (filesSeen: number) => void;
}

export interface WalkResult {
  entries: ManifestEntry[];
  skipped: { binary: number; large: number };
}

export class CancelledError extends Error {
  constructor() {
    super("Cancelled");
  }
}

interface Rules {
  dir: string; // relative to root, "" for the root
  ig: Ignore;
}

function ignored(rel: string, isDir: boolean, rules: Rules[]): boolean {
  for (const r of rules) {
    const sub = r.dir ? rel.slice(r.dir.length + 1) : rel;
    if (sub && r.ig.ignores(isDir ? sub + "/" : sub)) return true;
  }
  return false;
}

async function isBinary(full: string): Promise<boolean> {
  const fh = await fs.open(full, "r");
  try {
    const buf = Buffer.alloc(BINARY_SNIFF_BYTES);
    const { bytesRead } = await fh.read(buf, 0, BINARY_SNIFF_BYTES, 0);
    return buf.subarray(0, bytesRead).includes(0);
  } finally {
    await fh.close();
  }
}

export function hashFile(full: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash("sha256");
    createReadStream(full).on("data", (c) => h.update(c)).on("end", () => resolve(h.digest("hex"))).on("error", reject);
  });
}

export async function walkWorkspace(root: string, opts: WalkOptions): Promise<WalkResult> {
  const entries: ManifestEntry[] = [];
  const skipped = { binary: 0, large: 0 };
  const maxBytes = opts.maxFileSizeKB * 1024;
  const extra: Rules = { dir: "", ig: ignore().add(opts.extraExcludes) };
  let seen = 0;

  async function walk(dirRel: string, inherited: Rules[]) {
    if (opts.isCancelled?.()) throw new CancelledError();
    const dirFull = path.join(root, dirRel);
    let rules = inherited;
    try {
      const gi = await fs.readFile(path.join(dirFull, ".gitignore"), "utf8");
      rules = [...inherited, { dir: dirRel, ig: ignore().add(gi) }];
    } catch {
      // no .gitignore here
    }
    const items = await fs.readdir(dirFull, { withFileTypes: true });
    items.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const item of items) {
      const rel = dirRel ? `${dirRel}/${item.name}` : item.name;
      if (item.isSymbolicLink()) continue;
      if (item.isDirectory()) {
        if (SKIP_FOLDERS.has(item.name) || ignored(rel, true, rules)) continue;
        await walk(rel, rules);
      } else if (item.isFile()) {
        if (ignored(rel, false, rules)) continue;
        seen++;
        if (seen % 200 === 0) opts.onProgress?.(seen);
        const full = path.join(dirFull, item.name);
        const st = await fs.lstat(full);
        if (st.size > maxBytes) {
          skipped.large++;
          continue;
        }
        if (await isBinary(full)) {
          skipped.binary++;
          continue;
        }
        entries.push({ path: rel, sha256: await hashFile(full), size: st.size });
      }
    }
  }

  await walk("", [extra]);
  opts.onProgress?.(seen);
  return { entries, skipped };
}
