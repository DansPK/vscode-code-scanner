# Scanner harness

An MCP server that scans uploaded code (or a GitHub repo) with Semgrep, Gitleaks and SonarQube Community Edition, has an LLM review each finding, and lets the user chat about the results. The VS Code extension in `../vscode-extension` is its client.

## Setup

1. **Host setting (Linux only).** SonarQube needs `vm.max_map_count` of at least 262144:
   ```sh
   sudo sysctl -w vm.max_map_count=262144
   ```
   Docker Desktop on macOS and Windows already has this.
2. **Config.** `cp .env.example .env` and fill it in (see Configuration below).
3. **Start SonarQube first**, so you can make its token:
   ```sh
   docker compose up -d sonarqube sonar-db
   ```
   Open http://localhost:9000 and log in as `admin` / `admin` (you will be asked to change the password). Go to *My Account → Security* and create a **User** token for a user with the *Create Projects*, *Execute Analysis* and *Administer* (to delete projects) rights; the admin user has them all. A Global Analysis token is not enough, because the harness also reads issues and deletes projects. Put it in `.env` as `SONAR_TOKEN`.
4. **Start everything:**
   ```sh
   docker compose up -d --build
   curl http://localhost:8080/health    # {"status":"ok"}
   ```
5. **Create a user token.** It is printed once; only its hash is stored:
   ```sh
   docker compose exec harness harness-token alice --name "Alice"
   ```
   Give the token to the user. In VS Code they run *Vuln Scanner: Set Token*.

## HTTPS

The harness serves HTTPS itself when `HARNESS_TLS_CERT` and `HARNESS_TLS_KEY` point at a PEM certificate and key; otherwise it serves plain HTTP.

For local development, make a self-signed certificate:

```sh
scripts/make_dev_cert.sh                       # localhost, 127.0.0.1, ::1
scripts/make_dev_cert.sh 192.168.1.50 scan.lan # also for other names or IPs
```

This writes `certs/dev-cert.pem` and `certs/dev-key.pem`; compose mounts `./certs` at `/certs`. In `.env`:

```sh
HARNESS_PUBLIC_URL=https://localhost:8080
HARNESS_TLS_CERT=/certs/dev-cert.pem
HARNESS_TLS_KEY=/certs/dev-key.pem
```

In VS Code, set `vulnScanner.serverUrl` to `https://localhost:8080` and `vulnScanner.caCertificate` to the full path of `certs/dev-cert.pem`, so the extension trusts it. For a real deployment, use a certificate from a real CA, or put a reverse proxy in front.

## Configuration

All settings are environment variables. See the table in `IMPLEMENT_HARNESS.md` for the full list and defaults. Required: `HARNESS_PUBLIC_URL`, `HARNESS_TOKENS_FILE`, `HARNESS_SIGNING_SECRET`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`, `SONAR_HOST_URL`, `SONAR_TOKEN`. The compose file sets `HARNESS_TOKENS_FILE` and `SONAR_HOST_URL` for you.

`LLM_MODEL` uses LiteLLM's naming, for example `openai/qwen2.5-coder` for an OpenAI-compatible server. To reach an LLM on the Docker host, use `http://host.docker.internal:<port>/v1` as `LLM_BASE_URL`.

## Known limits

- **SonarQube Community Edition has no partial scan.** Every rescan analyses the whole project with SonarQube; only Semgrep and Gitleaks are incremental.
- **Java projects without compiled classes.** The scanner is pointed at an empty `sonar.java.binaries` folder so the analysis does not fail, but Java rules that need bytecode are skipped.
- **Secret masking** covers only secrets that Gitleaks or Semgrep's secrets rules detected.
- **Languages.** Semgrep rules for Python, Java, Kotlin, Scala, C#, JavaScript, TypeScript, React (JSX/TSX), Node.js, Go, PHP, Ruby, C, Rust, Swift, Terraform, Dockerfiles, Kubernetes and GitHub Actions are baked into the image. They come from 29 rule packs, merged into one file by `scripts/fetch_semgrep_rules.py` so overlapping packs don't report a problem twice, and scans work offline. Rebuild the image to update them. `tests/fixtures/polyglot_app` has one vulnerable sample per main language, and a test checks each one is caught.
- **SonarQube Community Edition** analyses Java, Kotlin, JS/TS (needs Node.js, included in the image), Python, PHP, Go, Ruby, Scala, HTML/CSS, XML, Docker and IaC files. **It cannot analyse C#, VB.NET, C or C++ with the CLI scanner**; those need the SonarScanner for .NET or a paid edition. Semgrep still covers C#.
- **Semgrep's free rules match patterns inside one file.** Well-structured code (for example Spring Data repositories) can give no Semgrep findings at all; SonarQube usually finds more there.
- **One scan per session at a time.** Scans run inside the harness process; a restart marks running scans as failed.
- **GitHub:** public repos, or private ones reachable with the server's own git credentials. Shallow clones only. The work tree is limited to `UPLOAD_MAX_UNPACKED_MB`.
- **Live findings.** While a scan runs, `get_findings` with that `scan_id` returns findings as soon as each scanner finishes, and each finding's LLM fields fill in as its review completes (an empty `explanation` means "not reviewed yet"). Without `scan_id`, `get_findings` still returns the latest *finished* scan.
- **Limits:** chat messages up to 8,000 characters; manifests up to 200,000 files; MCP requests up to 64 MB.

## Error messages

| Situation | What the user sees |
| --- | --- |
| A scanner binary is missing | Scan finishes as `done`; `error` says e.g. `gitleaks: gitleaks is not installed` |
| SonarQube is down | `error` says `sonarqube: SonarQube cannot be reached at ...`; the other tools' findings are kept |
| LLM is down | `error` says `llm: The LLM cannot be reached at ...`; findings have verdict `unsure`. Chat returns the same message. |
| Disk full | Upload returns HTTP 507; a scan fails with `The server disk is full.` |

Logs go to stderr, one line per record, tagged with `session=` and `scan=`. Tokens, upload signatures, API keys and secret values are never logged.

## Manual checks

- **Docker stack and SonarQube (Milestones 1, 2, 4):** done on 2026-10-04 with Docker Desktop on Apple Silicon and SonarQube Community 26.9.
  - `docker compose up` started all three services, `/health` returned OK, and every tool ran inside the image as the non-root user.
  - Scanning `tests/fixtures/vulnerable_app` through MCP took 45 s. It produced 15 findings: 3 from SonarQube (weak hashing CWE-1240, CSRF CWE-352 ×2), 1 merged Semgrep+Gitleaks, and 11 from Semgrep. All were reviewed by the real LLM.
  - After a container restart, the session, chat history and findings were all still there.
  - A rescan after editing `db.py` and deleting `auth.py` uploaded only `db.py`, finished in 13 s, and dropped the fixed and deleted findings.
  - The container logs held no tokens, keys, signatures or secrets.
  - SonarQube 26.x leaves `securityStandards` out of `/api/rules/show`, so the CWE is read from the `cwe` facet of `/api/rules/search`.
  - SonarQube's CWE numbers can differ from Semgrep's for the same problem (MD5: CWE-1240 vs CWE-327). Those findings then stay separate, because merging requires the same CWE.
- **Real LLM (Milestone 3):** done on 2026-10-04 against a local OpenAI-compatible server (LM Studio-style `/v1`, model `deephat-v1-7b-heretic-abliterated`, `LLM_MODEL=openai/deephat-v1-7b-heretic-abliterated`). The fixture app gave 12 findings; all 12 were reviewed (`likely_real`, sensible explanations, 7 with a patch) in about 1 to 3 minutes with `LLM_MAX_PARALLEL=2`. The chat answered "which finding is the worst and why?" using the tools. A first run showed this 7B model sometimes writes near-JSON (single-quoted strings, a patch as an object), so the parser now accepts that. Note: `LLM_MODEL` needs the `openai/` prefix for an OpenAI-compatible server.

## Development

```sh
uv sync
uv run pytest                                  # all tests
uv run pytest tests/test_auth.py::test_health  # one test
```

Scanner tests need `semgrep` and `gitleaks` on `PATH`. They are skipped if missing. To install project-local copies into `.bin/` (gitignored):

```sh
uv venv -p 3.12 .bin/semgrep-venv && uv pip install -p .bin/semgrep-venv semgrep
ln -sf "$PWD/.bin/semgrep-venv/bin/semgrep" .bin/semgrep
# download gitleaks for your OS from https://github.com/gitleaks/gitleaks/releases into .bin/
mkdir -p .bin/rules && uv run --with pyyaml python scripts/fetch_semgrep_rules.py .bin/rules/rules.yml
```

The tests put `.bin` on `PATH` and use `.bin/rules` automatically.
