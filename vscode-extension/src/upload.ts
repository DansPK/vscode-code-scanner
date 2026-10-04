// Send an archive to a presigned upload URL with an HTTP PUT, streaming the body.

import { createReadStream } from "fs";
import { Readable, Transform } from "stream";
import { FetchFn, tlsErrorCode } from "./http";

export class UploadError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const UPLOAD_MESSAGES: Record<number, string> = {
  400: "The upload did not match its size or hash. Please try again.",
  403: "The upload link was refused or has expired.",
  409: "The upload link was already used.",
  413: "The archive is larger than the server allows. Add excludes in vulnScanner.extraExcludes.",
  507: "The server disk is full.",
};

export async function uploadFile(url: string, file: string, size: number,
                                 onProgress?: (sent: number, total: number) => void,
                                 signal?: AbortSignal, fetchFn: FetchFn = fetch): Promise<void> {
  let sent = 0;
  const counter = new Transform({
    transform(chunk, _enc, cb) {
      sent += chunk.length;
      onProgress?.(sent, size);
      cb(null, chunk);
    },
  });
  const body = Readable.toWeb(createReadStream(file).pipe(counter)) as ReadableStream;
  let res: Response;
  try {
    res = await fetchFn(url, {
      method: "PUT", body, signal,
      headers: { "content-type": "application/gzip", "content-length": String(size) },
      // Required by Node's fetch for a streamed request body.
      duplex: "half",
    } as RequestInit);
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    if (tlsErrorCode(e)) throw new UploadError(0, "The upload failed: the server's HTTPS certificate is not trusted.");
    throw new UploadError(0, "The upload failed: the server cannot be reached.");
  }
  if (res.status === 201 || res.status === 200) return;
  throw new UploadError(res.status, UPLOAD_MESSAGES[res.status] ?? `The upload failed (HTTP ${res.status}).`);
}
