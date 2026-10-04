// HTTP for the MCP connection and uploads. With a CA certificate (for example the harness's
// self-signed dev certificate), that certificate is trusted in addition to the normal ones.

import { readFileSync } from "fs";
import * as os from "os";
import * as tls from "tls";
import { Agent, fetch as undiciFetch } from "undici";

export type FetchFn = (url: string | URL, init?: RequestInit) => Promise<Response>;

export function expandHome(p: string): string {
  return p.startsWith("~/") ? os.homedir() + p.slice(1) : p;
}

export function makeFetch(caCertificatePath?: string): FetchFn {
  if (!caCertificatePath) return fetch;
  let ca: string;
  try {
    ca = readFileSync(expandHome(caCertificatePath), "utf8");
  } catch {
    throw new Error(`Cannot read the CA certificate at ${caCertificatePath} (vulnScanner.caCertificate).`);
  }
  const dispatcher = new Agent({ connect: { ca: [...tls.rootCertificates, ca] } });
  return ((url: string | URL, init?: RequestInit) =>
    undiciFetch(url, { ...(init as object), dispatcher } as never)) as unknown as FetchFn;
}

const TLS_CODES = new Set(["DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN", "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "CERT_HAS_EXPIRED", "ERR_TLS_CERT_ALTNAME_INVALID", "CERT_UNTRUSTED"]);

/** The TLS error code somewhere in an error's cause chain, if any. */
export function tlsErrorCode(e: unknown): string | undefined {
  for (let cur = e as any, depth = 0; cur && depth < 6; cur = cur.cause, depth++) {
    if (typeof cur.code === "string" && TLS_CODES.has(cur.code)) return cur.code;
    const m = String(cur.message ?? "").match(/self[- ]signed certificate|unable to verify|certificate has expired|Hostname\/IP does not match/i);
    if (m) return m[0];
  }
  return undefined;
}
