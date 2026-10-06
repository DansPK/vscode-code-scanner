# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Two components, built from the plans in each folder (`IMPLEMENT_HARNESS.md`, `IMPLEMENT_VSCODE_EXTENSION.md`). The plans are the source of truth. Choices made where a plan was silent are recorded in each folder's `PLAN_QUESTIONS.md`.

## Commands

Harness (`analyzer-agent-harness/`, Python 3.12 via uv):

```sh
uv sync
uv run pytest                                    # all tests (~80 s)
uv run pytest tests/test_e2e.py::test_users_cannot_see_each_other   # one test
docker compose up -d --build                     # harness + SonarQube + Postgres (needs .env, see README)
docker compose exec harness harness-token <user> # create a user token (printed once)
```

Scanner tests need `semgrep` and `gitleaks`. Project-local copies live in `analyzer-agent-harness/.bin/` (gitignored), with the merged rules in `.bin/rules/rules.yml`. Rebuild them with `uv run --with pyyaml python scripts/fetch_semgrep_rules.py .bin/rules/rules.yml`, which the Dockerfile also uses. It merges 29 language and security packs and drops duplicate rules, because separate pack files would report each problem more than once. `tests/conftest.py` puts `.bin` on `PATH` and skips scanner tests if the tools are missing. `sonar-scanner` is not installed locally, so SonarQube always "fails" in tests, and tests assert the other tools carry on.

Extension (`vscode-extension/`, TypeScript, esbuild):

```sh
npm run build              # dist/extension.js + dist/webview.js
npm run test:unit          # node:test, no VS Code needed
npm run test:integration   # downloads VS Code into .vscode-test/ and opens a window briefly
node --test out/test/unit/flow.test.js   # one file, after `npm run compile-tests`
npm run fake-server        # fake harness on :7357, token "test-token"
```

`test/integration/runTest.ts` deletes `ELECTRON_RUN_AS_NODE`. Otherwise, when run from a VS Code terminal, the test VS Code starts as plain Node and dies.

## Architecture

```
VS Code extension ──MCP (streamable HTTP, /mcp, Bearer token)──► harness (Starlette + mcp SDK 2.x MCPServer)
        │                                                          ├─ Semgrep, Gitleaks, SonarScanner (parallel)
        └──HTTP PUT tar.gz to presigned /uploads/<id>?expires&sig─►├─ merge → LiteLLM review (cached per id+file hash)
                                                                   ├─ chat agent with sandboxed file tools
                                                                   └─ SQLite + files on /data
```

- **Shared contract.** Both plan files hold an identical "Shared contract" section, mirrored in `harness/service.py` (tool logic) and `vscode-extension/src/shared/contract.ts` (types). Change it in both plans and both implementations.
- **Harness layering.** `app.py` holds thin MCP tool wrappers. Each one reads the user from `ctx.headers` and turns `UserError` into `ToolError`. They call `service.Service`, which holds the session, sync and upload logic. Scans run as background asyncio tasks in `scans.ScanManager`. Progress is a condition variable plus the last message stored in the `scans` row, so late watchers still see it. `watch_scan` sends a heartbeat every 10 s.
- **Incremental scans.** Each scan saves its unmerged per-tool findings to `<data>/sessions/<sid>/scans/<scan>/raw/tool_findings.json`. A rescan combines:
  - new Semgrep and Gitleaks results for changed files,
  - earlier Semgrep and Gitleaks results for unchanged files,
  - new SonarQube results for the whole folder (Community Edition has no partial scan).

  Then `runner.finalize` runs: snippets first (so every tool's secret span is masked), then merge, then unique ids.
- **Stable finding ids** hash tool + rule + path + trimmed start-line text, never the line number. Statuses, the review cache and merging depend on this.
- **Secrets.** Gitleaks runs with `--redact`, so the harness never sees secret values. Masking uses the column spans the tools report (`_mask` on each finding, stored in `findings.masks`), for snippets, LLM prompts and chat `read_file`/`search_code`.
- **SonarQube's JS/TS analysis needs Node.js LTS in the image.** SonarQube 26.x refuses Debian's Node 20, so the Dockerfile installs the official Node 24 build. The SonarScanner CLI cannot analyse C#.
- **Semgrep always gets explicit file targets.** Its default ignore list skips `tests/`, and explicit targets bypass it. Test fixtures are copied to a temp folder before scanning for the same reason.
- **Extension layering.** Pure Node modules (`client.ts`, `scanFlow.ts`, `workspaceFiles.ts`, `archive.ts`, `upload.ts`, `routing.ts`, `findingsLogic.ts`) are unit-tested against `test/fakeServer.ts`. `controller.ts` is the only VS Code glue for state, diagnostics and editor navigation. The webview (`webview/main.ts`) talks only to the controller, through the message types in `src/shared/messages.ts`.
- **`Controller.connect()`** awaits `doConnect()` (connection only), and only then loads sessions through `ready()`. Loading inside the same promise deadlocks, because `ready()` awaits `connecting`.

- **Chat drives scans.** The only scan button is **Rescan** (it lights up after you save files that have findings; no chat suggestion). `Controller.send` sends every message to `chat`; the harness first asks the LLM for a JSON routing decision (`intent.decide`), then either runs the normal chat agent or returns a reply with an `action` (`scan`, `scan_workspace`, `scan_github`, `cancel`; `full`, `paths`, `confirm`). The extension runs the action, or shows Yes/No first when `confirm` is set. If `chat` fails with an LLM error, `keywordAction` (the old `routing.ts` rules) takes over for scan commands. `start_scan`'s `paths` limits a scan to folders; `ScanManager._carry_over` keeps every finding outside that scope. The test fake LLM answers routing calls from `FakeLLMCompletion.intents`.
- **Fix agent and summary.** `fix_findings` (`harness/agent.py`) runs one tool-calling agent per file with findings (`LLM_MAX_PARALLEL` at once) over a shared in-memory copy (`Edits`: real, masked and original lines). Tools: `read_file`, `search_code`, `edit_file` (exact unique text on the masked view; refused if it would write back `****`), `check_fixes`, `finish`. Checks rerun Semgrep with only the targets' rules (all 1000+ rules take ~50 s to load, a few take ~4 s) plus Gitleaks; a finding is still reported if its id survives or its rule fires as often in that file as before. `line_edits` turns the result into whole-line edits; a single blank line borrows a neighbour, since `""` means delete. Without tool calling (or if the server rejects tools) it falls back to `fix.propose`, one-shot edits per finding. The agent's LLM calls stream (`LLM.complete(on_text=...)`, rebuilt with `litellm.stream_chunk_builder`; `reasoning_content` streams as thinking); its text, tool and result events go out as JSON progress messages, text batched every 0.25 s, and the extension draws them as a live transcript block (`agentStart`/`agentEvent`/`agentEnd`). Small files (≤300 lines) go into the agent's task whole, which saves a `read_file` call; the rules are parsed once per process, preloaded at startup. The extension (`Controller.fixFindings`) groups the result per file (several files: **Apply all** or **Review one by one**), refuses if the file is dirty or its hash differs from `file_sha256`, shows a `vscode.diff` against a virtual `vulnscanner-fix:` document, and applies plus saves only after **Apply fix**. Chat intents `fix` (action with `finding_ids`, chosen by `service.fix_targets`) and `summary`. `chat.summarize` is short: two lines of counts, then the LLM's one sentence and at most three "fix first" bullets (`_concise` cuts anything else); with nothing likely real it skips the LLM. After every scan the extension calls `summarize_findings` (not saved in history) and draws its `card` (`summaryCard` message: severity bar, overall, clickable fix-first items with Fix buttons, most affected files, Fix all / View findings). Messages starting with "fix" or "summarize" skip the routing LLM call.
- **Web tools.** With `WEB_SEARCH_URL` set (compose runs a `searxng` container, internal only, JSON API on), the chat agent and the fix agent also get `web_search` and `fetch_url` (`harness/web.py`). Queries are cut to 200 chars and refused if they contain `****`; the prompt forbids code, secrets and project names in them. `fetch_url` only reads public addresses: every resolved IP must be `is_global`, checked again on each redirect (followed by hand), 2 MB / 8000 chars, text only. Set `WEB_SEARCH_URL=` empty in `.env` to turn them off.
- **Live findings.** `ScanManager._run` stores merged findings after each scanner finishes (`db.save_findings(..., replace=True)`), stores the full list before the LLM step, then updates each finding as its review completes (`db.update_finding`). The extension's `Controller.liveFindings` re-fetches `get_findings(scan_id=<running>)` on progress, at most every 1.5 s. An empty `explanation` means "not reviewed yet".
- **HTTPS.** The harness serves TLS when `HARNESS_TLS_CERT`/`HARNESS_TLS_KEY` are set; `scripts/make_dev_cert.sh` makes a self-signed dev certificate in `certs/`. The extension trusts an extra CA through `vulnScanner.caCertificate`: `src/http.ts` builds an undici `fetch` with that CA, used for both MCP and uploads.

## Rules that hold everywhere

- A token pasted into the `vulnScanner.token` setting is moved to SecretStorage and the setting is cleared (`takeTokenFromSettings`). Never read the token from settings in any other way.
- Never log, store or post tokens (including users' GitHub tokens for private repos, which pass through `start_scan` to git's environment only), upload signatures (`logs.RedactingFormatter` scrubs `sig=`; uvicorn runs with `log_config=None`), API keys, secret values or (extension side) file contents.
- Harness config comes only from environment variables (`config.py`). `LLM_MODEL` needs LiteLLM's provider prefix, for example `openai/<model>` for an OpenAI-compatible server. Small local models often return near-JSON, and `llm.parse_review` accepts it.
- Contract paths are relative, use forward slashes, and have no `..` or empty parts (`files.check_rel_path`). Unpacking refuses links, devices and absolute or `..` paths before anything reaches the code folder. GitHub clones have every symlink removed.
