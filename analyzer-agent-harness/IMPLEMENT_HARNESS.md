# Implementation plan: Scanner harness (MCP server)

This file is for a coding agent. It explains what to build, in what order, and how to check each step. It contains no code on purpose. Make your own design choices where this file is silent, and keep them simple.

The matching file for the VS Code extension is `IMPLEMENT_VSCODE_EXTENSION.md`. Both files share the same "Shared contract" section.

## What you are building

A Python service that runs in Docker. It is an MCP server. A VS Code extension connects to it and asks it to scan source code for vulnerabilities.

The harness:

- Receives a project as a tar.gz upload, or clones a GitHub repo.
- Runs three scanners: Semgrep, Gitleaks, and SonarQube Community Edition.
- Merges the results into one list of findings.
- Asks an LLM to review each finding, explain it, and suggest a fix.
- Streams progress back to the extension.
- Keeps sessions, chat history, file manifests, and findings in a database.
- Lets the user chat with an agent about the code and the findings.

The harness never has direct access to the user's files. It only sees what is uploaded or cloned.

## Rules for the coding agent

- Work through the milestones in order. Finish each one, including its checks, before you start the next.
- Write tests as you go. Run them before you call a milestone done.
- Never print to stdout from library code. Use the logging module.
- Never log tokens, upload signatures, API keys, or secret values found by Gitleaks.
- Keep every setting in environment variables, read in one config module. No hard-coded URLs, keys, or model names.
- If something in this file is unclear or seems wrong, write your question in `PLAN_QUESTIONS.md` and pick the simplest safe option.

## Technology

| Need | Use |
| --- | --- |
| Language | Python 3.12 |
| MCP server | The official `mcp` Python SDK, with the streamable HTTP transport |
| HTTP app | Starlette or FastAPI. Mount MCP at `/mcp`. Add the upload route and a `/health` route on the same app. |
| Server | uvicorn |
| LLM | LiteLLM, calling an OpenAI-compatible endpoint |
| Database | SQLite, through SQLAlchemy or the standard `sqlite3` module |
| Tests | pytest |
| Scanners | Semgrep (pip), Gitleaks (binary), SonarScanner CLI (binary, includes its own Java), git |
| Containers | Docker Compose |

## Configuration

Read all of these from environment variables. Give safe defaults where it makes sense. Fail at startup with a clear message if a required one is missing.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `HARNESS_HOST` / `HARNESS_PORT` | no | `0.0.0.0` / `8080` | Where the server listens |
| `HARNESS_PUBLIC_URL` | yes | | Base URL the extension uses. Needed to build upload URLs. |
| `HARNESS_TOKENS_FILE` | yes | | Path to the tokens file (see Milestone 1) |
| `HARNESS_SIGNING_SECRET` | yes | | Secret used to sign upload URLs |
| `HARNESS_DATA_DIR` | no | `/data` | Root folder for the database, sessions, and uploads |
| `UPLOAD_MAX_MB` | no | `200` | Largest archive accepted |
| `UPLOAD_MAX_UNPACKED_MB` | no | `1000` | Largest total size after unpacking |
| `UPLOAD_URL_TTL_SECONDS` | no | `600` | How long an upload URL stays valid |
| `LLM_BASE_URL` | yes | | OpenAI-compatible base URL of your local LLM |
| `LLM_API_KEY` | yes | | API key for that LLM |
| `LLM_MODEL` | yes | | Model name, as LiteLLM expects it (for example `openai/<name>`) |
| `LLM_CONTEXT_TOKENS` | no | `32000` | Context size of the model |
| `LLM_TIMEOUT_SECONDS` | no | `120` | Timeout per LLM call |
| `LLM_MAX_PARALLEL` | no | `2` | How many review calls run at once |
| `LLM_TOOL_CALLING` | no | `true` | Whether the model supports tool calling |
| `SEMGREP_CONFIGS` | no | rules folder in the image | Semgrep rule sets to use |
| `SONAR_HOST_URL` | yes | | URL of the SonarQube container |
| `SONAR_TOKEN` | yes | | SonarQube token with rights to create projects and run analysis |
| `SONAR_ISSUE_TYPES` | no | `VULNERABILITY,BUG` | Issue types to import, plus security hotspots |
| `GIT_CLONE_TIMEOUT_SECONDS` | no | `300` | Timeout for clone and pull |

## Data layout

- `<data>/harness.db`: the SQLite database.
- `<data>/sessions/<session_id>/code/`: the current code for the session.
- `<data>/sessions/<session_id>/scans/<scan_id>/raw/`: raw output from each tool (`semgrep.json`, `gitleaks.json`, `sonarqube.json`).
- `<data>/uploads/`: archives waiting to be used. Delete each one after it is unpacked, or after it expires.

Database tables, at a minimum:

- `sessions`: id, owner user, name, target type, repo URL, created and updated times, last commit (for GitHub).
- `messages`: session id, role (user or assistant), text, finding ids, time.
- `manifest_files`: session id, path, sha256, size. This is the current manifest.
- `pending_manifests`: session id, the manifest from the last `sync_files`, time.
- `uploads`: upload id, session id, declared size and hash, expiry, used flag, stored file path.
- `scans`: the scan summary fields from the contract.
- `findings`: the finding fields from the contract, plus scan id and session id.
- `llm_reviews`: a cache keyed by finding id and file hash, holding verdict, explanation, fix, and patch.

The data folder must be a Docker volume, so everything survives a restart.

## Shared contract (same text in both plan files)

This section is the contract between the VS Code extension and the harness. Both sides must follow it exactly. If you need to change it, change it in both plan files.

### Transport and login

- MCP runs over streamable HTTP at the path `/mcp` on the harness.
- Every MCP request carries the header `Authorization: Bearer <token>`.
- Each token belongs to one user. The harness rejects a missing or unknown token with HTTP 401.
- File uploads do not go through MCP. They use a presigned URL (see "Upload flow").

### Paths and hashes

- All file paths are relative to the workspace root.
- Paths use forward slashes, even on Windows. No leading slash. No `..` parts.
- Hashes are SHA-256, written as 64 lowercase hex characters.

### Manifest

A manifest is a list of entries, one per file. Each entry has:

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | string | Relative path, as above |
| `sha256` | string | Hash of the file's bytes |
| `size` | integer | Size in bytes |

### Upload flow (used for the first scan and every rescan)

The first scan and a rescan use the same steps. On the first scan, the harness has no stored manifest, so it asks for every file.

1. The extension builds the manifest for the whole workspace.
2. The extension calls `sync_files` with the manifest.
3. The harness compares it with its stored manifest. It returns `need` (new or changed paths) and `delete` (paths it has that are no longer in the manifest). It saves the new manifest as "pending" for this session.
4. If `need` is empty and `delete` is empty, there is nothing to upload. The extension tells the user that nothing changed. It may still start a scan if the user asked for a full rescan.
5. If `need` is not empty, the extension packs only those files into a tar.gz. Each file sits at its relative path inside the archive.
6. The extension calls `request_upload` with the archive size and hash.
7. The harness returns a one-time `upload_url`.
8. The extension sends the archive with an HTTP `PUT` to `upload_url`. The body is the raw archive bytes. The content type is `application/gzip`.
9. The extension calls `start_scan` with the `upload_id` (if any) and the `delete` list.
10. The harness unpacks the archive, checks each file's hash against the pending manifest, deletes the listed paths, and makes the pending manifest the current one. Then it scans.

Responses from the upload URL:

| HTTP status | Meaning |
| --- | --- |
| 201 | Stored and the hash matches |
| 400 | Size or hash does not match what `request_upload` declared |
| 403 | Signature is wrong or the URL has expired |
| 409 | This URL was already used |
| 413 | Archive is larger than the server limit |

### MCP tools

All tools return JSON objects. On error, the tool returns an MCP error result with a short, human-readable message.

| Tool | Inputs | Output |
| --- | --- | --- |
| `create_session` | `name` (optional), `target_type` (`workspace` or `github`), `repo_url` (required for `github`) | `session_id` |
| `list_sessions` | none | list of sessions: `session_id`, `name`, `target_type`, `repo_url`, `created_at`, `last_scan_at`, `last_scan_status` |
| `get_session` | `session_id`, `message_limit` (default 50) | `session` fields, `messages` (oldest first), `latest_scan_id`, `file_count` |
| `rename_session` | `session_id`, `name` | `ok` |
| `delete_session` | `session_id` | `ok` |
| `sync_files` | `session_id`, `manifest` | `need` (list of paths), `delete` (list of paths), `unchanged_count` |
| `request_upload` | `session_id`, `size_bytes`, `sha256` | `upload_id`, `upload_url`, `expires_at` |
| `start_scan` | `session_id`, `upload_id` (optional), `deleted_paths` (optional), `full` (optional boolean, default false) | `scan_id` |
| `watch_scan` | `scan_id` | Sends progress notifications while the scan runs. Returns the final scan summary when it ends. |
| `get_scan_status` | `scan_id` | scan summary (see below) |
| `cancel_scan` | `scan_id` | `ok` |
| `get_findings` | `session_id`, `scan_id` (optional, default latest), `severity` (optional list), `tool` (optional list), `path` (optional), `limit` (default 200), `offset` (default 0) | `findings`, `total` |
| `chat` | `session_id`, `message` | `reply` (Markdown text), `finding_ids` (findings the reply talks about) |

Rules:

- A user can only see and change their own sessions. Any other `session_id` returns "session not found".
- For a `github` session, `sync_files` and `request_upload` are not used. `start_scan` clones the repo the first time and pulls after that.
- Only one scan runs per session at a time. A second `start_scan` while one is running returns an error.
- Each `chat` call is saved to the session's history, both the user message and the reply.

### Scan summary

| Field | Type | Meaning |
| --- | --- | --- |
| `scan_id` | string | |
| `session_id` | string | |
| `status` | string | `queued`, `running`, `done`, `failed`, or `cancelled` |
| `stage` | string | `preparing`, `semgrep`, `gitleaks`, `sonarqube`, `merging`, `llm_review`, or `finished` |
| `percent` | integer | 0 to 100, a rough estimate |
| `counts` | object | Number of findings per severity |
| `error` | string or null | Set when `status` is `failed` |
| `started_at`, `finished_at` | ISO 8601 strings | |

### Progress notifications

- The extension calls `watch_scan` with an MCP progress token.
- The harness sends MCP progress notifications on that token. Each one has `progress` (0 to 100), `total` (100), and `message` (one short line, like "Semgrep: 120 files scanned").
- The harness must send a notification at least every 15 seconds, even if nothing changed. This keeps the client's timeout from firing.
- When the scan ends, `watch_scan` returns the scan summary.
- If the connection drops, the extension calls `get_scan_status`, then `watch_scan` again if the scan is still running.

### Finding

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stable id. Hash of tool, rule id, path, and the trimmed code line. The same problem keeps the same id across scans. |
| `tools` | list of strings | Tools that reported it (`semgrep`, `gitleaks`, `sonarqube`). More than one after merging. |
| `rule_id` | string | The rule that fired, from the first tool |
| `title` | string | Short name of the problem |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `cwe` | string or null | For example `CWE-89`, when known |
| `path` | string | Relative file path |
| `start_line`, `end_line` | integer | 1-based, inclusive |
| `start_col`, `end_col` | integer or null | 1-based |
| `file_sha256` | string | Hash of the file when it was scanned. The extension uses it to tell if the finding may be out of date. |
| `message` | string | The tool's own message |
| `snippet` | string | A few lines of code around the finding. Secrets are masked. |
| `verdict` | string | `likely_real`, `likely_false_positive`, or `unsure` |
| `explanation` | string | Plain explanation from the LLM |
| `fix_recommendation` | string | Plain steps to fix it, from the LLM |
| `suggested_patch` | string or null | Optional suggested replacement code, as text |
| `status` | string | `new` (first seen in this scan) or `existing` (seen in an earlier scan) |
| `web_url` | string or null | For `github` sessions only: a link to the file and line on GitHub |

## Milestones

### Milestone 1: Skeleton, login, and Docker

Build:

- The project layout, the config module, logging, and the HTTP app with `/health` and `/mcp`.
- A tokens file. It is a small YAML or JSON file. Each entry has a user id, a display name, and the SHA-256 of that user's token. The plain token is never stored.
- A small command-line helper that creates a new random token for a user, prints it once, and adds its hash to the tokens file.
- Auth for `/mcp`. Read the bearer token, hash it, and find the user. Compare hashes in constant time. Pass the user id to every tool call.
- One temporary tool, `whoami`, that returns the user id. Remove it at the end of Milestone 4.
- A Dockerfile for the harness. It installs Python, Semgrep, Gitleaks, the SonarScanner CLI, and git. Run as a non-root user.
- A `docker-compose.yml` with three services: `harness`, `sonarqube` (the Community Edition image), and `sonar-db` (Postgres, for SonarQube). Named volumes for the harness data, SonarQube data, and the database.
- A `README.md` that explains setup. Include the host setting SonarQube needs (`vm.max_map_count` of at least 262144 on Linux hosts) and how to create the SonarQube token.

Check:

- `docker compose up` starts all three services, and `/health` returns OK.
- An MCP test client with a valid token can call `whoami`.
- A request with no token, or a wrong token, gets HTTP 401.
- Unit tests for token hashing and lookup pass.

### Milestone 2: Scanners and the finding format

Build a scanner module that takes a folder and returns a list of findings in the contract format, without the LLM fields yet.

- **Semgrep.** Run it on the folder with JSON output and metrics turned off. Bake the rule sets into the Docker image at build time, so scans work without internet. Start with Semgrep's general security rules and its secrets rules. Map severity: `ERROR` to high, `WARNING` to medium, `INFO` to low. Take the CWE from the rule's metadata when present.
- **Gitleaks.** Run it in directory mode (not git mode), with JSON output and redaction turned on. Every Gitleaks finding is high. Mask any secret value in the message and the snippet. Keep only the first 4 characters, then asterisks.
- **SonarQube.** Use one SonarQube project per session. The project key is based on the session id. Run the SonarScanner CLI on the folder with that key. Wait for the server to finish processing (poll the compute engine task until it succeeds or fails). Then read issues through the web API, filtered by `SONAR_ISSUE_TYPES`. Also read security hotspots. Map severity: `BLOCKER` to critical, `CRITICAL` to high, `MAJOR` to medium, `MINOR` to low, `INFO` to info. Hotspots are medium unless their probability is high. For Java projects without compiled classes, set the scanner so it does not fail. Note this limit in the README.
- **Snippets.** For each finding, read about 5 lines before and after from the file. Mask secrets.
- **Stable ids.** Build the id from the tool, the rule id, the path, and the trimmed text of the start line. Do not use the line number, so a finding keeps its id when lines move.
- **Merging.** Two findings are the same problem if they are in the same file, their line ranges overlap, and they have the same CWE. If neither has a CWE, the rule titles must be close. Keep one finding, list all its tools, and keep the highest severity.
- **Running.** Run the three scanners side by side. If one fails, keep the others' results. Record the failure in the scan summary's `error` field, and still mark the scan as `done`.
- Save each tool's raw output in the scan's `raw` folder.

Check:

- Add a folder `tests/fixtures/vulnerable_app/`. Put in a few small files with known problems: a hard-coded API key, an SQL query built by joining user input, use of MD5 for passwords, and a shell command built from user input.
- A test runs Semgrep and Gitleaks on that folder and finds each planted problem.
- A test for merging, with two fake findings on the same line from different tools.
- A test that no secret value appears in any finding or log line.
- A manual check against the real SonarQube container, written down in the README.

### Milestone 3: LLM review and chat

Build:

- An LLM client module that wraps LiteLLM with the config values. Add a timeout and one retry on network errors.
- **Review step.** For each finding, send the rule, the tool message, the file path, and about 40 lines of code around the finding. Ask for a JSON reply with `verdict`, `explanation`, `fix_recommendation`, and `suggested_patch`. Ask for plain language. Validate the reply. If it is not valid JSON, retry once with a short reminder. If it still fails, set the verdict to `unsure` and say the review failed.
- Respect `LLM_CONTEXT_TOKENS`. If the code around a finding is too long, cut it down to fit.
- Run at most `LLM_MAX_PARALLEL` reviews at once.
- Cache each review by finding id plus file hash. If both are the same in a later scan, reuse the review without calling the LLM.
- **Chat agent.** The `chat` tool sends the user's message, the recent chat history, and a short summary of the latest findings to the LLM.
    - If `LLM_TOOL_CALLING` is true, give the agent these internal tools: `list_findings` (with filters), `get_finding` (by id), `read_file` (path and line range), and `search_code` (plain text search, with a limit on results).
    - All file tools must stay inside the session's `code` folder. Resolve the full path and refuse anything outside it, including through symlinks.
    - Stop after 8 tool steps and answer with what the agent has.
    - If `LLM_TOOL_CALLING` is false, do not offer tools. Put the findings summary and any file the user names into the prompt instead.
    - The agent cannot start a scan for a workspace session, because only the extension can upload files. If the user asks, the agent tells them to click Rescan.
    - Save both the user message and the reply in `messages`.

Check:

- With a fake LLM (a test double that returns fixed replies), the review fills every finding's LLM fields.
- A bad JSON reply leads to one retry, then `unsure`.
- A second run with the same findings makes no LLM calls.
- `read_file` refuses `../` paths and absolute paths.
- A manual check against your real local LLM, written down in the README.

### Milestone 4: Sessions, uploads, scans, and progress

Build all the MCP tools in the shared contract.

- **Sessions.** `create_session`, `list_sessions`, `get_session`, `rename_session`, `delete_session`. Deleting a session removes its folder, its database rows, and its SonarQube project.
- **sync_files.** Validate every path (forward slashes, relative, no `..`, no empty parts). Compare with the current manifest. Save the new manifest as pending. Return `need`, `delete`, and `unchanged_count`.
- **request_upload.** Check the declared size against `UPLOAD_MAX_MB`. Create an upload id. Build the URL `<HARNESS_PUBLIC_URL>/uploads/<upload_id>` with an expiry time and an HMAC signature. The signature covers the upload id, session id, expiry, size, and hash, using `HARNESS_SIGNING_SECRET`.
- **Upload route.** `PUT /uploads/<upload_id>`. It needs no bearer token, because the signature is the proof. Check the signature and expiry. Refuse a used URL. Stream the body to disk without loading it all into memory. Stop as soon as it passes the size limit. Check the final size and hash. Mark the upload as used. Return the status codes from the contract.
- **Safe unpacking.** Unpack into a temporary folder first. Refuse the whole archive if any entry has an absolute path, a `..` part, a symlink, a hard link, or a device file. Stop if the unpacked size passes `UPLOAD_MAX_UNPACKED_MB`. Every unpacked file must be in the pending manifest, with a matching hash. Then move the files into the session's `code` folder, delete the paths in `deleted_paths`, and make the pending manifest current.
- **start_scan.** Create the scan row with status `queued`, start the scan as a background task, and return the `scan_id` at once. Refuse a second scan while one is running for the same session.
- **Incremental scans.** If the session already had a scan and `full` is false:
    - Run Semgrep and Gitleaks only on changed and new files.
    - Copy the earlier findings for unchanged files into the new scan.
    - Drop the earlier findings for changed and deleted files.
    - Run SonarQube on the whole folder, because the Community Edition has no partial scan.
    - Run the LLM review only on findings that are not in the review cache.
- Set each finding's `status` to `new` or `existing` by comparing ids with the previous scan.
- **watch_scan.** Send progress notifications as described in the contract. Send one at each stage change, one for each batch of LLM reviews, and a heartbeat at least every 15 seconds.
- **get_scan_status**, **cancel_scan**, and **get_findings**, with the filters and paging in the contract. Cancelling stops the running scanner processes and marks the scan `cancelled`.
- Clean up expired uploads on a timer.
- Remove the `whoami` tool.

Check:

- An end-to-end test with an MCP test client: create a session, sync, upload the fixture project, start a scan, watch it to the end, and read findings.
- Edit one fixture file and delete another. A second sync returns exactly one path in `need` and one in `delete`. The rescan keeps the other findings and updates the edited file's findings.
- Upload tests: wrong hash gives 400, expired URL gives 403, a reused URL gives 409, and an archive over the limit gives 413.
- Unpacking tests: archives with `../evil`, `/etc/passwd`, and a symlink are each refused, and nothing is written.
- A user cannot read another user's session.
- A restart of the container keeps sessions, messages, and findings.

### Milestone 5: GitHub sessions

Build:

- For a `github` session, the first `start_scan` clones the repo into the session's `code` folder. Use a shallow clone. Use the server's own Git credentials, if it has any. Never take credentials from the tool input.
- Accept only `https://github.com/<owner>/<repo>` URLs, with an optional `.git` ending. Refuse anything else.
- A later `start_scan` fetches and moves to the latest commit. Use the Git diff between the old and new commit to find changed, new, and deleted files. Then follow the incremental scan rules.
- Build the manifest from the cloned files, so the rest of the code works the same way.
- Set `web_url` on each finding: `https://github.com/<owner>/<repo>/blob/<commit>/<path>#L<start>-L<end>`.
- Apply a clone timeout and a size limit.

Check:

- Scanning a small public repo works, and every finding has a working `web_url`.
- A bad URL, such as a different host, is refused.
- A rescan with no new commits says nothing changed and keeps the findings.

### Milestone 6: Hardening

- Clear error messages for each failure: a scanner is missing, SonarQube cannot be reached, the LLM cannot be reached, or the disk is full.
- Structured logs with the session id and scan id, and no secrets.
- A size limit for chat messages and tool inputs.
- Update the README with setup, configuration, and known limits.

## Done means

- All the checks in every milestone pass.
- `docker compose up` on a clean machine, plus the README steps, gives a working server.
- The VS Code extension, built from its own plan, can run a full scan and a rescan against this server.
