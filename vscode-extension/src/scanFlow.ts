// The upload and scan flows from the contract, without VS Code APIs.

import { Archive, createArchive, formatBytes, largestFolders, removeArchive } from "./archive";
import { HarnessClient, ServerUnreachableError, ToolCallError } from "./client";
import type { Finding, ManifestEntry, ScanSummary } from "./shared/contract";
import { UploadError, uploadFile } from "./upload";
import { walkWorkspace } from "./workspaceFiles";

export interface FlowSettings {
  maxFileSizeKB: number;
  maxUploadMB: number;
  extraExcludes: string[];
}

export interface FlowUI {
  walking?: (filesSeen: number) => void;
  uploading?: (sent: number, total: number) => void;
  isCancelled?: () => boolean;
  signal?: AbortSignal;
}

export interface Prepared {
  /** Nothing to upload and nothing deleted since the last sync. */
  nothingChanged: boolean;
  uploadId?: string;
  deleted: string[];
  uploaded: string[];
  fileCount: number;
}

export class TooLargeError extends Error {}

const RECONNECT_ATTEMPTS = 6;
const FINDINGS_PAGE = 200;

/** Steps 1-8 of the upload flow: manifest, sync, pack the needed files, upload. */
export async function prepareWorkspace(client: HarnessClient, sessionId: string, root: string,
                                       settings: FlowSettings, ui: FlowUI = {}): Promise<Prepared> {
  const { entries } = await walkWorkspace(root, {
    maxFileSizeKB: settings.maxFileSizeKB, extraExcludes: settings.extraExcludes,
    isCancelled: ui.isCancelled, onProgress: ui.walking,
  });
  const sync = await client.syncFiles(sessionId, entries);
  const base = { deleted: sync.delete, fileCount: entries.length };
  if (sync.need.length === 0) {
    return { ...base, nothingChanged: sync.delete.length === 0, uploaded: [] };
  }
  let archive: Archive | undefined;
  try {
    archive = await createArchive(root, sync.need);
    if (archive.size > settings.maxUploadMB * 1024 * 1024) {
      const byPath = new Map(entries.map((e) => [e.path, e] as [string, ManifestEntry]));
      const folders = largestFolders(sync.need.map((p) => byPath.get(p)!).filter(Boolean))
        .map((f) => `- \`${f.folder}\` ${formatBytes(f.bytes)}`).join("\n");
      throw new TooLargeError(`The archive is ${formatBytes(archive.size)}, more than the limit of `
        + `${settings.maxUploadMB} MB (vulnScanner.maxUploadMB). The largest folders are:\n${folders}\n\n`
        + "Add excludes in vulnScanner.extraExcludes or .gitignore, then try again.");
    }
    let uploadId = "";
    for (let attempt = 1; ; attempt++) {
      const ticket = await client.requestUpload(sessionId, archive.size, archive.sha256);
      try {
        await uploadFile(ticket.upload_url, archive.file, archive.size, ui.uploading, ui.signal, client.fetchFn);
        uploadId = ticket.upload_id;
        break;
      } catch (e) {
        // An expired link gets one more try with a fresh one.
        if (e instanceof UploadError && e.status === 403 && attempt === 1) continue;
        throw e;
      }
    }
    return { ...base, nothingChanged: false, uploadId, uploaded: sync.need };
  } finally {
    await removeArchive(archive);
  }
}

/** Watch a scan to its end, following progress. If the connection drops, check the
 * status and watch again while the scan is still running. */
export async function watchToEnd(client: HarnessClient, scanId: string,
                                 onProgress: (percent: number, message: string) => void,
                                 signal?: AbortSignal): Promise<ScanSummary> {
  let failures = 0;
  for (;;) {
    try {
      return await client.watchScan(scanId, onProgress, signal);
    } catch (e) {
      if (signal?.aborted || e instanceof ToolCallError) throw e;
      failures++;
      if (failures > RECONNECT_ATTEMPTS) throw e;
      await sleep(Math.min(500 * 2 ** (failures - 1), 10_000));
      let status: ScanSummary;
      try {
        status = await client.getScanStatus(scanId);
      } catch (e2) {
        if (e2 instanceof ServerUnreachableError) continue;
        throw e2;
      }
      if (status.status !== "running" && status.status !== "queued") return status;
      onProgress(status.percent, "Reconnected; still scanning");
    }
  }
}

/** All findings of the latest finished scan, or of `scanId` (for example a scan that is still running). */
export async function fetchAllFindings(client: HarnessClient, sessionId: string, scanId?: string): Promise<Finding[]> {
  const all: Finding[] = [];
  for (let offset = 0; ; offset += FINDINGS_PAGE) {
    const page = await client.getFindings(sessionId, { limit: FINDINGS_PAGE, offset, scan_id: scanId });
    all.push(...page.findings);
    if (page.findings.length === 0 || all.length >= page.total) return all;
  }
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}
