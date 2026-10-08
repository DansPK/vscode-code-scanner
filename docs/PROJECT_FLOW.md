# Project flow

How a request travels through vscode-code-scanner: from typing in the chat panel, through the harness and its scanners, to findings in the editor and fixes applied to files.

For setup see [SETUP.md](SETUP.md). For the exact API see the "Shared contract" section in either plan file ([harness](harness/IMPLEMENT_HARNESS.md), [extension](extension/IMPLEMENT_VSCODE_EXTENSION.md)).

## 1. The pieces

```mermaid
flowchart LR
  subgraph VSCode["VS Code"]
    WV["Webview chat panel<br/>webview/main.ts"]
    CT["Controller<br/>src/controller.ts"]
    FL["Pure modules<br/>scanFlow, archive, upload,<br/>workspaceFiles, client"]
    ED["Editor: diagnostics,<br/>diffs, navigation"]
    WV <-- "messages.ts" --> CT
    CT --> FL
    CT --> ED
  end

  subgraph Docker["Docker compose"]
    H["Harness<br/>Starlette + MCP"]
    SQ["SonarQube + Postgres"]
    SX["SearXNG (optional)"]
    DB[("SQLite + files<br/>/data")]
    H --> SQ
    H --> SX
    H --> DB
  end

  LLM["LLM server<br/>(via LiteLLM)"]

  FL -- "MCP over HTTP(S) /mcp<br/>Bearer token" --> H
  FL -- "PUT tar.gz to<br/>presigned /uploads/&lt;id&gt;" --> H
  H --> LLM
```

| Piece | Role |
| --- | --- |
| Webview ([main.ts](../vscode-extension/webview/main.ts)) | Draws the chat, progress, findings, summary card and fix transcript. Talks only to the controller. |
| Controller ([controller.ts](../vscode-extension/src/controller.ts)) | The only VS Code glue: token, sessions, scans, diagnostics, diffs, applying fixes. |
| Pure modules (`src/*.ts`) | Walk and hash files, pack the tar.gz, upload, call MCP tools. Unit-tested without VS Code. |
| Harness ([app.py](../analyzer-agent-harness/src/harness/app.py)) | Thin MCP tool wrappers. Each one reads the user from the token and calls `Service`. |
| Service ([service.py](../analyzer-agent-harness/src/harness/service.py)) | Sessions, file sync, uploads, chat routing, summary, fix requests. |
| ScanManager ([scans.py](../analyzer-agent-harness/src/harness/scans.py)) | Runs scans as background asyncio tasks and publishes progress and partial findings. |
| Scanners (`harness/scanners/`) | Semgrep, Gitleaks and SonarScanner run in parallel; results are merged. |
| LLM ([llm.py](../analyzer-agent-harness/src/harness/llm.py)) | Reviews findings, routes chat, answers questions, runs the fix agent. |

## 2. Connecting

```mermaid
sequenceDiagram
  participant U as User
  participant C as Controller
  participant S as SecretStorage
  participant H as Harness
  U->>C: Set Token (or paste into vulnScanner.token)
  C->>S: store token (setting is cleared)
  C->>H: MCP connect /mcp, Authorization: Bearer token
  H-->>C: 401 if unknown token, else connected
  C->>H: list_sessions
  H-->>C: this user's sessions only
  C-->>U: chat panel ready
```

- Tokens are made on the server with `harness-token <user>`; each one maps to one user.
- `connect()` finishes the connection first, then loads sessions through `ready()`.
- With `vulnScanner.caCertificate` set, both MCP and uploads trust that CA ([http.ts](../vscode-extension/src/http.ts)).

## 3. Chat decides what happens

Every message goes to the `chat` tool. The harness decides what it means.

```mermaid
flowchart TD
  M["User types a message"] --> SEND["Controller.send → chat(session_id, message)"]
  SEND --> PRE{"Starts with<br/>'fix' or 'summarize'?"}
  PRE -- yes --> ROUTE
  PRE -- no --> DEC["intent.decide<br/>LLM returns a JSON routing decision"]
  DEC --> ROUTE{"Decision"}
  ROUTE -- none --> AG["Chat agent with sandboxed tools:<br/>list/get findings, read_file,<br/>search_code, web_search, fetch_url"]
  ROUTE -- summary --> SUM["chat.summarize"]
  ROUTE -- fix --> FX["service.fix_targets picks finding ids"]
  ROUTE -- scan / scan_workspace /<br/>scan_github / cancel --> ACT["Reply with an action"]
  AG --> REP["reply + finding_ids, saved to history"]
  SUM --> REP
  FX --> REP2["reply + action: fix"]
  ACT --> REP2
  REP2 --> CONF{"action.confirm?"}
  CONF -- yes --> YN["Yes / No buttons"]
  CONF -- no --> RUN["Controller.runAction"]
  YN -- Yes --> RUN
  RUN --> SC["scan → §4/§5"]
  RUN --> FIX["fix → §7"]
  RUN --> CAN["cancel_scan"]
```

- Only the extension can upload files or change the workspace, so scans and fixes come back as actions that the extension carries out.
- If `chat` fails with an LLM error, `keywordAction` ([routing.ts](../vscode-extension/src/routing.ts)) recognises plain scan commands so scanning still works.
- The only scan button is **Rescan**. It lights up after you save a file that has findings.

## 4. Workspace scan: sync and upload

The first scan and every rescan use the same steps. Only changed files are uploaded.

```mermaid
sequenceDiagram
  participant C as Extension (scanFlow.prepareWorkspace)
  participant H as Harness
  C->>C: walk workspace (skip list, .gitignore, size limit), hash each file
  C->>H: sync_files(manifest)
  H->>H: compare with stored manifest, save new one as "pending"
  H-->>C: need[], delete[]
  alt need is empty
    C->>C: "No files changed" (unless full / paths scan or last scan didn't finish)
  else need has files
    C->>C: pack only "need" files into tar.gz (refuse if > maxUploadMB)
    C->>H: request_upload(size, sha256)
    H-->>C: upload_id, one-time presigned upload_url
    C->>H: HTTP PUT tar.gz (403 once → retry with a fresh URL)
    H-->>C: 201 stored, hash matches
  end
  C->>H: start_scan(upload_id, deleted_paths, full?, paths?)
  H->>H: unpack (refuse links, devices, absolute or .. paths),<br/>check hashes vs pending manifest, delete paths,<br/>pending manifest becomes current
  H-->>C: scan_id
```

**GitHub sessions** skip all of this: `start_scan` clones the repo the first time (symlinks removed) and pulls after that. Findings get a `web_url` to the line on GitHub.

## 5. Running a scan (harness side)

`ScanManager._run` runs in the background. Only one scan runs per session.

```mermaid
flowchart TD
  P["preparing<br/>pick targets: in scope (paths)<br/>and changed, unless full"] --> CH{"Anything to scan?"}
  CH -- no --> KEEP["Keep previous findings"]
  CH -- yes --> PAR
  subgraph PAR["Run in parallel"]
    SG["Semgrep<br/>changed files, explicit targets"]
    GL["Gitleaks<br/>changed files, --redact"]
    SQ["SonarQube<br/>whole folder"]
  end
  PAR -- "each tool done →<br/>merge + save partial findings" --> LIVE[("findings table")]
  PAR --> CARRY["Add earlier Semgrep/Gitleaks results<br/>for unchanged or out-of-scope files"]
  KEEP --> FIN
  CARRY --> FIN["runner.finalize:<br/>1. snippets + mask secret spans<br/>2. merge duplicates across tools<br/>3. stable ids"]
  FIN --> STORE["Mark new / existing,<br/>apply cached reviews, save all"]
  STORE --> REV["llm_review: each finding not yet reviewed<br/>→ verdict, explanation, fix steps<br/>(LLM_MAX_PARALLEL at once, cached per id + file hash)"]
  REV -- "each review →<br/>update_finding" --> LIVE
  REV --> DONE["finished: counts, errors per tool"]
```

Key rules:

- **Stable ids** hash tool + rule + path + the trimmed start-line text, not the line number. Statuses, review caching and merging rely on this.
- **Secrets never leave masked.** Gitleaks runs with `--redact`, and the column spans the tools report are masked in snippets, LLM prompts and the chat's `read_file` / `search_code`.
- **A tool failing doesn't fail the scan.** Its error goes into the summary's `error`, and the other tools' results are kept.
- Each scan saves its raw per-tool findings to `raw/tool_findings.json`, which the next incremental scan reuses.

## 6. Watching progress and showing findings

```mermaid
sequenceDiagram
  participant W as Webview
  participant C as Controller
  participant H as Harness
  C->>H: watch_scan(scan_id) with MCP progress token
  loop while running
    H-->>C: progress(percent, message), at least every 10 s
    C-->>W: progress bar + message
    C->>H: get_findings(scan_id=running), at most every 1.5 s
    C-->>W: live findings (empty explanation = not reviewed yet)
  end
  H-->>C: final scan summary
  Note over C,H: Connection drops → get_scan_status,<br/>watch again if still running (watchToEnd)
  C->>H: get_findings (paged, 200 at a time)
  C->>C: set diagnostics, mark findings whose file hash changed as outdated
  C->>H: summarize_findings (not saved to history)
  H-->>C: card: counts, overall sentence, fix-first items, top files
  C-->>W: summaryCard with Fix / Fix all / View findings
```

Clicking a finding opens the file at its line. `chat.summarize` skips the LLM when nothing is likely real.

## 7. Fixing findings

Starts from a **Fix** / **Fix all** button or a chat message like "fix all high findings".

```mermaid
sequenceDiagram
  participant W as Webview
  participant C as Controller
  participant H as Harness (agent.py)
  participant L as LLM
  C->>H: fix_findings(session_id, finding_ids)
  par one agent per file with findings (LLM_MAX_PARALLEL)
    H->>L: task (small files included whole), streamed
    L-->>H: tool calls: read_file, search_code, edit_file,<br/>check_fixes, web_search, finish
    H->>H: edits go to a shared in-memory copy (masked view;<br/>edits writing back **** are refused)
    H->>H: check_fixes: Semgrep with only the targets' rules + Gitleaks
    H-->>C: progress JSON {file, kind, text}
    C-->>W: live transcript (thinking, text, tool, result)
  end
  H-->>C: files[] (whole-line edits + file_sha256), summary, results[] per finding
  C->>C: refuse a file that is dirty or whose hash ≠ file_sha256
  C-->>W: several files → Apply all / Review one by one
  C->>C: show vscode.diff against a virtual vulnscanner-fix: document
  W->>C: Apply fix
  C->>C: write and save the file
```

- Nothing changes on either side until you click **Apply fix**. The harness only works on its copy.
- Each finding comes back `fixed`, `still_reported`, `not_verified` (SonarQube can't recheck a single file) or `not_fixed`.
- If the model or server can't do tool calling, `fix.propose` makes one-shot edits per finding instead.
- Workspace sessions only, and not while a scan runs.

## 8. Rescan loop

```mermaid
flowchart LR
  A["Edit and save a file<br/>that has findings"] --> B["Rescan button lights up"]
  B --> C["Rescan → §4: only changed<br/>files uploaded"]
  C --> D["§5: Semgrep/Gitleaks on changed files,<br/>SonarQube on the whole folder,<br/>earlier results kept for the rest"]
  D --> E["Same id → status 'existing',<br/>cached review reused"]
  E --> F["Updated diagnostics + summary card"]
  F --> A
```

## 9. Where things live on the server

```
/data
├── harness.db                      sessions, messages, scans, findings, review cache
├── uploads/                        archives waiting for start_scan
└── sessions/<session_id>/
    ├── code/                       current copy of the workspace or clone
    └── scans/<scan_id>/raw/
        └── tool_findings.json      unmerged per-tool findings, reused by the next scan
```

At startup the harness recovers scans that were interrupted, preloads the Semgrep rules for the fix agent, and starts a background loop that removes old uploads.
