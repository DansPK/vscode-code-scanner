import assert from "node:assert/strict";
import { execFileSync } from "child_process";
import { promises as fs, readFileSync } from "fs";
import * as os from "os";
import * as path from "path";
import { after, before, test } from "node:test";
import { HarnessClient } from "../../src/client";
import { makeFetch } from "../../src/http";
import { prepareWorkspace } from "../../src/scanFlow";
import { FakeHarness } from "../fakeServer";
import { makeTree } from "./helpers";

let fake: FakeHarness;
let certFile = "";

before(async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "cert-"));
  certFile = path.join(dir, "cert.pem");
  const keyFile = path.join(dir, "key.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "2", "-nodes",
    "-keyout", keyFile, "-out", certFile, "-subj", "/CN=test",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE"],
  { stdio: "ignore" });
  fake = new FakeHarness({ stepMs: 20, tls: { cert: readFileSync(certFile, "utf8"), key: readFileSync(keyFile, "utf8") } });
  await fake.start();
});
after(() => fake.stop());

test("an untrusted self-signed certificate gives a clear message", async () => {
  const c = new HarnessClient(fake.url, fake.token);
  await assert.rejects(c.connect(), /certificate is not trusted.*vulnScanner\.caCertificate/s);
});

test("with the CA certificate: connect, upload and scan over HTTPS", async () => {
  assert.ok(fake.url.startsWith("https://"));
  const c = new HarnessClient(fake.url, fake.token, makeFetch(certFile));
  await c.connect();
  const { session_id } = await c.createSession("workspace");
  const root = await makeTree({ "a.js": "a" });
  const p = await prepareWorkspace(c, session_id, root, { maxFileSizeKB: 100, maxUploadMB: 10, extraExcludes: [] });
  assert.ok(p.uploadId);
  assert.ok(fake.lastUploadArchive());
  await c.close();
});

test("a missing CA file is reported by name", () => {
  assert.throws(() => makeFetch("/nope/cert.pem"), /Cannot read the CA certificate at \/nope\/cert\.pem/);
});
