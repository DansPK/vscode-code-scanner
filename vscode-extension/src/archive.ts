// Pack files into a tar.gz at their relative paths, and describe what is in it.

import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import * as tar from "tar";
import type { ManifestEntry } from "./shared/contract";
import { hashFile } from "./workspaceFiles";

export interface Archive {
  file: string;
  dir: string;
  size: number;
  sha256: string;
}

export async function createArchive(root: string, paths: string[]): Promise<Archive> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vuln-scanner-"));
  const file = path.join(dir, "upload.tar.gz");
  try {
    await tar.create({ gzip: true, cwd: root, file, portable: true, noDirRecurse: true, follow: false }, paths);
    const size = (await fs.stat(file)).size;
    return { file, dir, size, sha256: await hashFile(file) };
  } catch (e) {
    await removeArchive({ file, dir, size: 0, sha256: "" });
    throw e;
  }
}

export async function removeArchive(a: Archive | undefined) {
  if (a) await fs.rm(a.dir, { recursive: true, force: true });
}

export async function listArchive(file: string): Promise<string[]> {
  const names: string[] = [];
  await tar.list({ file, onReadEntry: (e) => { names.push(e.path); } });
  return names;
}

/** The biggest top-level folders (or root files) among the given files, largest first. */
export function largestFolders(entries: ManifestEntry[], n = 5): { folder: string; bytes: number }[] {
  const sums = new Map<string, number>();
  for (const e of entries) {
    const parts = e.path.split("/");
    const key = parts.length > 1 ? parts.slice(0, Math.min(2, parts.length - 1)).join("/") + "/" : "(root files)";
    sums.set(key, (sums.get(key) ?? 0) + e.size);
  }
  return [...sums.entries()].map(([folder, bytes]) => ({ folder, bytes }))
    .sort((a, b) => b.bytes - a.bytes).slice(0, n);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
