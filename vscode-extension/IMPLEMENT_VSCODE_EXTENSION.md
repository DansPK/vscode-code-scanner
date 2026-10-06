# Implementation plan: VS Code extension (MCP client)

This file is for a coding agent. It explains what to build, in what order, and how to check each step. It contains no code on purpose. Make your own design choices where this file is silent, and keep them simple.

The matching file for the server is `IMPLEMENT_HARNESS.md`. Both files share the same "Shared contract" section.

## What you are building

A VS Code extension that scans source code for vulnerabilities. It does not scan anything itself. It is an MCP client that talks to a scanner harness running in Docker.

The extension:

- Shows a chat panel. The user talks to it in plain language, and can also chat with the agent that runs in the harness.
- Scans the open workspace, or a GitHub link the user types.
- For a workspace, packs the files into a tar.gz with a SHA-256 hash for each file, and uploads it.
- On Rescan, sends only the files that changed.
- Shows live progress while a scan runs.
- Shows each finding with its explanation and fix recommendation. Clicking a finding opens the file at the right line.
- Supports sessions. The user can create, switch, rename, and delete them. Sessions are stored on the harness.

## Rules for the coding agent

- Work through the milestones in order. Finish each one, including its checks, before you start the next.
- Write tests as you go. Run them before you call a milestone done.
- Never write the token to settings, logs, or the webview. Keep it only in VS Code secret storage.
- Never send a file the user's ignore rules exclude.
- If something in this file is unclear or seems wrong, write your question in `PLAN_QUESTIONS.md` and pick the simplest safe option.

## Technology

| Need | Use |
| --- | --- |
| Language | TypeScript, strict mode |
| VS Code API | A recent stable version (1.90 or newer) |
| MCP client | The official `@modelcontextprotocol/sdk`, with the streamable HTTP client transport |
| Archive | The `tar` npm package, with gzip |
| Ignore rules | The `ignore` npm package, for `.gitignore` files |
| Hashing | Node's built-in `crypto` |
| Upload | Node's built-in `fetch`, with a streamed body |
| Chat UI | A webview view in the sidebar. Plain HTML, CSS, and TypeScript are enough. Use VS Code theme colors so it fits light and dark themes. |
| Markdown in chat | A small Markdown renderer, with HTML turned off |
| Bundling | esbuild |
| Tests | The VS Code extension test runner, plus plain unit tests for logic that does not need VS Code |

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `vulnScanner.serverUrl` | empty | Base URL of the harness, for example `https://scanner.example.com` |
| `vulnScanner.maxFileSizeKB` | `2048` | Files larger than this are skipped |
| `vulnScanner.maxUploadMB` | `200` | Stop before uploading an archive larger than this |
| `vulnScanner.extraExcludes` | `[]` | Extra glob patterns to skip |
| `vulnScanner.showLikelyFalsePositives` | `false` | Whether to show findings the LLM marked as likely false alarms |

## Commands

| Command | What it does |
| --- | --- |
| `Vuln Scanner: Set Token` | Asks for the token in a password box and saves it in secret storage |
| `Vuln Scanner: Clear Token` | Removes the token |
| `Vuln Scanner: Open Chat` | Shows the chat panel |
| `Vuln Scanner: New Session` | Creates a new session |
| `Vuln Scanner: Scan Workspace` | Same as typing "scan this project" |
| `Vuln Scanner: Rescan` | Sends changed files and rescans |
| `Vuln Scanner: Cancel Scan` | Cancels the running scan |

## Default skip list

Always skip these, in addition to `.gitignore` rules and `vulnScanner.extraExcludes`:

- Folders: `.git`, `node_modules`, `build`, `dist`, `out`, `target`, `bin`, `obj`, `.venv`, `venv`, `__pycache__`, `.idea`, `.vscode`.
- Binary files. Treat a file as binary if its first 8 KB contains a zero byte.
- Files larger than `vulnScanner.maxFileSizeKB`.
- Symlinks. Do not follow them.

Read `.gitignore` files in every folder, not only the root. Each one applies to its own folder and below.

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
| `start_scan` | `session_id`, `upload_id` (optional), `deleted_paths` (optional), `full` (optional boolean, default false), `paths` (optional list of folders or files to limit the scan to; findings for other files are kept from the previous scan), `github_token` (optional; `github` sessions only: the user's own GitHub token for a private repository, used for this clone or fetch only, never stored or logged) | `scan_id` |
| `watch_scan` | `scan_id` | Sends progress notifications while the scan runs. Returns the final scan summary when it ends. |
| `get_scan_status` | `scan_id` | scan summary (see below) |
| `cancel_scan` | `scan_id` | `ok` |
| `get_findings` | `session_id`, `scan_id` (optional, default latest), `severity` (optional list), `tool` (optional list), `path` (optional), `limit` (default 200), `offset` (default 0) | `findings`, `total` |
| `chat` | `session_id`, `message` | `reply` (Markdown text), `finding_ids` (findings the reply talks about), `action` (a chat action, or null) |
| `summarize_findings` | `session_id` | `summary` (short Markdown about the latest finished scan: counts, the most affected files, and up to three things to fix first), `finding_ids`, and `card`, the same as data: `total`, `counts` (per severity), `likely_real`, `false_alarms`, `files` (up to three `{path, count}`), `overall` (one sentence or null), `fix_first` (up to three `{text, finding_ids}`; the ids are not repeated in `text`). Not saved in the chat history; the extension draws `card` after each scan. |
| `fix_findings` | `session_id`, `finding_ids` (from the latest finished scan, at most 200) | Runs the fix agent. Streams its work as progress notifications (see "Fix agent events"). Returns a fix result (see below). Nothing is changed on either side. |

Rules:

- A user can only see and change their own sessions. Any other `session_id` returns "session not found".
- For a `github` session, `sync_files` and `request_upload` are not used. `start_scan` clones the repo the first time and pulls after that. If the clone fails without a `github_token`, the error message contains "If the repository is private, sign in to GitHub and scan again." so the extension can offer a sign-in.
- Only one scan runs per session at a time. A second `start_scan` while one is running returns an error.
- Each `chat` call is saved to the session's history, both the user message and the reply.
- `get_findings` with the `scan_id` of a running scan returns the findings found so far. A finding whose `explanation` is empty has not been reviewed by the LLM yet.
- `fix_findings` works only for `workspace` sessions, and not while a scan runs.

### Chat action

The agent decides what each chat message asks for. When it wants a scan started or stopped, or findings fixed, the `chat` reply carries an action. The extension carries it out, because only the extension can upload or change workspace files. A request for a summary of all findings needs no action: the reply is the summary.

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | string | `scan` (the session's own target: the workspace, or the GitHub repo), `scan_workspace` (the local workspace, asked from a GitHub session), `scan_github` (the repo in `url`), `cancel` (stop the running scan), or `fix` (call `fix_findings` with `finding_ids`) |
| `full` | boolean | Scan everything again, not only changed files |
| `paths` | list of strings | Folders or files to limit the scan to; empty means everything |
| `url` | string or null | For `scan_github`: `https://github.com/<owner>/<repo>` |
| `confirm` | boolean | The agent is not sure: ask the user (Yes/No) before acting |
| `finding_ids` | list of strings | For `fix`: the findings to fix, most serious first (at most 200; more than 10 come with `confirm` set); empty otherwise |

### Fix agent events

The `message` of each `fix_findings` progress notification is a JSON object `{"file", "kind", "text"}`, so the extension can show a live transcript. `file` is the file an agent works on, or null for the whole request. Several files are worked on at once, so events of different files interleave.

| `kind` | `text` |
| --- | --- |
| `start` | An agent starts on `file`, for example "3 findings" |
| `thinking` | A piece of the model's reasoning, streamed; append it to the previous `thinking` text |
| `text` | A piece of the model's reply, streamed; append it to the previous `text` |
| `tool` | One line per tool call, for example "Read db.py" or "Edit db.py" |
| `result` | One short line about the last tool's result, for example "+2 −1 lines" |
| `status` | A line about the request, for example "Checking all changes with the scanners" |
| `done` | The agent for `file` finished, for example "Finished 2 of 5 files" |
| `heartbeat` | Nothing to show; sent at least every 10 seconds to keep the request alive |

### Fix result

What `fix_findings` returns. A coding agent on the harness reads and searches the code, edits files (any file, not only the finding's), and reruns the scanners on its changes. It works on a copy of the uploaded code. The extension shows the changes as diffs and changes a file only after the user accepts, and only if the file's current hash equals `file_sha256`.

| Field | Type | Meaning |
| --- | --- | --- |
| `files` | list | One entry per changed file: `path`, `file_sha256` (hash of the file the edits were made for), and `edits`. Each edit has `start_line`, `end_line` (1-based, inclusive) and `replacement` (the new text for those whole lines, without a final newline; empty deletes them). Edits are sorted and never overlap. |
| `summary` | string | Markdown: what the agent changed and why |
| `results` | list | One entry per requested finding: `finding_id`, `status`, and `note` (one plain sentence). `status` is `fixed` (the scanners no longer report it), `still_reported`, `not_verified` (changed, but SonarQube cannot recheck one file), or `not_fixed` (its file was not changed; `note` says why). |

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

## Messages between the extension and the webview

The webview never talks to the harness directly. It sends messages to the extension, and the extension does the work. Define these message types in one shared file.

From the webview to the extension:

- `ready`: the webview has loaded.
- `send`: the user sent a chat message, with its text.
- `scan`, `rescan`, `cancel`: button clicks.
- `newSession`, `switchSession` (with an id), `renameSession` (with an id and a name), `deleteSession` (with an id).
- `openFinding`: the user clicked a finding, with its id.

From the extension to the webview:

- `state`: connection status, the session list, the current session, and whether a scan is running.
- `history`: the chat messages for the current session.
- `message`: one new chat message, from the user or the assistant.
- `progress`: the percent and the message line for the running scan.
- `findings`: the findings list for the current session.
- `error`: a short error to show in the chat.

## Milestones

### Milestone 1: Project setup and a fake harness

Build:

- The extension project, with esbuild, the settings, the commands, and an empty chat panel.
- A small fake MCP server for tests. It is a Node script that serves the MCP tools in the shared contract, with fixed answers. It also serves the upload URL and checks the hash. It sends a few progress notifications in `watch_scan`. Use it for all tests, so the extension can be built before the real harness is ready.

Check:

- The extension loads in the development host, and the chat panel opens.
- The fake server starts in the test setup.

### Milestone 2: Connection and token

Build:

- `Set Token` and `Clear Token`, using secret storage.
- A connection manager. It creates the MCP client with the streamable HTTP transport. It points at `<serverUrl>/mcp` and adds the `Authorization: Bearer <token>` header to every request.
- Connect when the chat panel opens. Reconnect when the server URL or the token changes.
- If the server returns 401, show "Token rejected. Run Vuln Scanner: Set Token." in the chat.
- If there is no server URL or no token, show a short message with a button that runs the right command.
- Show the connection status at the top of the chat panel.

Check:

- With the fake server, a valid token connects and an invalid one shows the 401 message.
- The token does not appear in the settings file, in the output logs, or in any webview message.

### Milestone 3: Chat panel and sessions

Build:

- The chat panel: a message list, a text box, a send button, and Scan, Rescan, and Cancel buttons.
- Assistant replies are Markdown. Render them with HTML turned off. Code blocks get a copy button.
- A session picker at the top: a list, plus New, Rename, and Delete. Ask before deleting.
- On switch, call `get_session` and show its history and latest findings.
- Remember the last session for each workspace folder, in workspace state. Open it again next time.
- Chat routing. Check each message in this order:
    1. If it contains a GitHub link (`https://github.com/<owner>/<repo>`), start a GitHub scan. Create a new `github` session for that link if the current session is not already for it.
    2. If it is a rescan request (the word "rescan", or "scan again"), run the rescan flow.
    3. If it asks to scan the project ("scan", "analyze", or "check", together with "this", "project", "workspace", "code", or "folder"), run the workspace scan flow.
    4. Otherwise, send it to the `chat` tool and show the reply.
- Keep the routing rules in one function with unit tests. It must be easy to change later.
- While waiting for a chat reply, show a "thinking" line.

Check:

- Unit tests for the routing function, with at least ten example messages.
- Creating, switching, renaming, and deleting sessions works against the fake server.
- After a VS Code restart, the same session opens with its history.

### Milestone 4: Packing, hashing, and upload

Build:

- **Choosing the folder.** Use the workspace folder. If there are several, ask the user to pick one. If no folder is open, say so in the chat.
- **Walking the files.** Apply the default skip list, `.gitignore` rules, and `vulnScanner.extraExcludes`. Show a progress notice while walking, with a cancel button.
- **Manifest.** For each file, record the relative path with forward slashes, the SHA-256, and the size. Read files as streams, so large projects do not fill memory.
- **Sync.** Call `sync_files` with the manifest. Use its `need` list for the archive.
- **Archive.** Pack only the `need` files into a tar.gz in a temporary folder. Each file sits at its relative path. Hash the archive and read its size.
- **Size check.** If the archive is larger than `vulnScanner.maxUploadMB`, stop. Tell the user the size and the five largest folders, so they can add excludes.
- **Upload.** Call `request_upload`. Send the archive with an HTTP PUT to `upload_url`, with the body as a stream and the content type `application/gzip`. Show upload progress. Handle the status codes in the contract with clear messages. If the URL expired (403), ask for a new one and try once more.
- Delete the temporary archive when done, even after an error.

Check:

- Unit tests on a sample folder: ignored files and skipped folders are left out, binary and large files are skipped, paths use forward slashes, and hashes are correct.
- The archive contains exactly the `need` files.
- Against the fake server, the upload succeeds, and a wrong hash gives a clear error.

### Milestone 5: Scans and live progress

Build:

- **Workspace scan.** Make sure there is a `workspace` session for this folder. Run Milestone 4's flow. Then call `start_scan` with the `upload_id` and the `delete` list.
- **Rescan.** The same flow. If `need` and `delete` are both empty, say "No files changed since the last scan" and do not start a scan.
- **Progress.** Call `watch_scan` with a progress handler. Turn on the SDK's option that resets the request timeout each time a progress notification arrives. Also set a long overall limit, such as two hours. Show each progress message in the chat as one updating line, not a new line each time.
- **Reconnect.** If `watch_scan` fails because the connection dropped, call `get_scan_status`. If the scan is still running, call `watch_scan` again.
- **Cancel.** The Cancel button calls `cancel_scan`.
- **Result.** When the scan ends, show a short summary in the chat: the number of findings by severity, how many are new, and any scanner that failed. Then load findings.
- **GitHub scan.** Call `start_scan` with no upload, then follow the same progress steps.
- Only one scan at a time per session. Disable Scan and Rescan while one runs.

Check:

- Against the fake server, progress lines update, the final summary appears, and Cancel works.
- A simulated dropped connection recovers and shows the final result.
- Editing one file and clicking Rescan sends an archive with only that file.

### Milestone 6: Findings and navigation

Build:

- **Findings list in the chat.** Group by severity (critical first), then by file. Each item shows the title, file and line, verdict, and tools. Clicking an item expands it to show the explanation, the fix recommendation, and the suggested patch (if any) with a copy button.
- Hide findings with the verdict `likely_false_positive` unless `vulnScanner.showLikelyFalsePositives` is on. Show how many are hidden.
- **Go to line.** Each item has an "Open" link. For a workspace session, open the file and select the lines from `start_line` to `end_line`. For a GitHub session, open `web_url` in the browser.
- **Out-of-date check.** Before opening a workspace file, compare its current hash with the finding's `file_sha256`. If they differ, show a small note: "This file changed since the scan. The line may have moved. Click Rescan to update."
- **Editor markers.** Add each workspace finding to a diagnostic collection, so it shows as a squiggle and in the Problems panel. Map critical and high to Error, medium to Warning, and low and info to Information. The diagnostic message is the title plus the first sentence of the fix recommendation. Clear and refill the collection when the session or the findings change.
- Use paging with `get_findings` if `total` is larger than one page.

Check:

- Clicking a finding opens the right file and selects the right lines.
- Problems panel entries match the findings list.
- Editing a file shows the out-of-date note on its findings.
- A GitHub finding opens the browser at the right line.

### Milestone 7: Polish

- Clear messages for every error: server unreachable, token rejected, upload too large, scan failed, scan already running.
- An output channel for logs, with no tokens and no file contents.
- Keyboard support in the chat panel: Enter sends, Shift+Enter adds a new line.
- A `README.md` with setup steps, settings, and screenshots of the chat panel.

## Done means

- All the checks in every milestone pass.
- Against the real harness, a user can set a token, type "scan this project", watch progress, click a finding to jump to its line, edit a file, click Rescan, and see only that file uploaded.
- Closing and reopening VS Code brings back the same session and its history.
