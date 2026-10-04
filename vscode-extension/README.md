# Vuln Scanner for VS Code

Scan your code for vulnerabilities from a chat panel in the sidebar. The scanning itself runs on a self-hosted **scanner harness** (see `../analyzer-agent-harness`): Semgrep, Gitleaks and SonarQube find problems, and an LLM explains each one and suggests a fix. This extension is the client. It uploads your files, shows live progress, and lists the findings in the chat and in the Problems panel.

## Setup

1. Run the harness (see its README) and get a token from its admin (`harness-token <you>`).
2. In VS Code settings, set **`vulnScanner.serverUrl`**, for example `http://localhost:8080`.
3. Run **Vuln Scanner: Set Token** and paste the token, or paste it into the `vulnScanner.token` setting. Either way it ends up only in VS Code's secret storage; the setting is cleared right away.
4. For HTTPS with a self-signed certificate, set `vulnScanner.caCertificate` to the certificate file (see the harness README).
5. Open the **Vuln Scanner** view in the activity bar (the shield icon).

## Using it

Type in the chat:

| You type | What happens |
| --- | --- |
| `scan this project` (or "analyze the code", "check this folder") | Scans the open workspace folder |
| `rescan` / `scan again` | Sends only the files that changed since the last scan, then rescans |
| a GitHub link, e.g. `https://github.com/owner/repo` | Scans that repo on the server (a new GitHub session) |
| anything else | Asks the agent about your code and findings |

The **Scan**, **Rescan** and **Cancel** buttons do the same. Enter sends; Shift+Enter adds a new line.

**Findings** appear while the scan runs, as each scanner finishes; ones the LLM has not reviewed yet say *Reviewing…*. They are grouped by severity, then by file. Expand one to read the explanation, how to fix it, and a suggested patch (with a copy button). **Open** jumps to the lines in the editor, or opens GitHub for a GitHub session. If the file changed since the scan, you get a note to rescan. Workspace findings also show as squiggles and in the Problems panel.

**Sessions** live on the server. Use the picker at the top to switch, and New, Rename or Delete to manage them. The last session for each workspace opens again next time.

## What is uploaded

Only files under the chosen workspace folder, skipping:
- `.git`, `node_modules`, `build`, `dist`, `out`, `target`, `bin`, `obj`, `.venv`, `venv`, `__pycache__`, `.idea`, `.vscode`
- anything your `.gitignore` files exclude (every folder's `.gitignore` applies to that folder and below)
- `vulnScanner.extraExcludes` patterns, binary files, files over `vulnScanner.maxFileSizeKB`, and symlinks

On a rescan, only new and changed files are sent. Before uploading, the extension stops if the archive is over `vulnScanner.maxUploadMB` and lists the largest folders, so you can exclude them.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `vulnScanner.serverUrl` | empty | Base URL of the harness (`http://` or `https://`) |
| `vulnScanner.token` | empty | Paste a token here to sign in; it moves to secure storage and this field is cleared |
| `vulnScanner.caCertificate` | empty | PEM certificate to trust for HTTPS (for a self-signed harness), in addition to the normal ones |
| `vulnScanner.maxFileSizeKB` | `2048` | Files larger than this are skipped |
| `vulnScanner.maxUploadMB` | `200` | Stop before uploading an archive larger than this |
| `vulnScanner.extraExcludes` | `[]` | Extra patterns to skip (gitignore syntax) |
| `vulnScanner.showLikelyFalsePositives` | `false` | Show findings the LLM marked as likely false alarms |

## Commands

*Vuln Scanner:* Set Token, Clear Token, Open Chat, New Session, Scan Workspace, Rescan, Cancel Scan.

Logs are in the **Vuln Scanner** output channel. They never contain your token or file contents.

## Development

```sh
npm install
npm run build              # bundle with esbuild into dist/
npm run test:unit          # plain Node tests (routing, file walk, archive, upload and scan flows vs. the fake harness)
npm run test:integration   # runs inside a downloaded VS Code against the fake harness
npm test                   # both
node --test out/test/unit/routing.test.js   # one unit test file (after npm run compile-tests)
npm run fake-server        # fake harness on http://127.0.0.1:7357, token "test-token", for trying the UI by hand
```

Press F5 with this folder open to start an Extension Development Host. The integration tests open a second VS Code window for a few seconds; it closes on its own.
