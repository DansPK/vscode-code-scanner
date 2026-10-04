# Vuln Scanner for VS Code

Scan your code for vulnerabilities from a chat panel in the sidebar. The scanning itself runs on a self-hosted **scanner harness** (see `../analyzer-agent-harness`): Semgrep, Gitleaks and SonarQube find problems, and an LLM explains each one and suggests a fix. This extension is the client. It uploads your files, shows live progress, and lists the findings in the chat and in the Problems panel.

## Setup

1. Run the harness (see its README) and get a token from its admin (`harness-token <you>`).
2. In VS Code settings, set **`vulnScanner.serverUrl`**, for example `http://localhost:8080`.
3. Run **Vuln Scanner: Set Token** and paste the token, or paste it into the `vulnScanner.token` setting. Either way it ends up only in VS Code's secret storage; the setting is cleared right away.
4. For HTTPS with a self-signed certificate, set `vulnScanner.caCertificate` to the certificate file (see the harness README).
5. Open the **Vuln Scanner** view in the activity bar (the shield icon).

## Using it

There are no scan buttons: you tell the assistant what you want, in your own words. Every message goes to the agent on the harness, which answers questions and starts or stops scans:

| You type, for example | What happens |
| --- | --- |
| "scan this project", "check my changes", "rescan" | Sends only the files that changed since the last scan, then scans |
| "scan everything again from scratch" | A full scan |
| "scan only the backend api", "just check src/auth" | Scans only that folder; findings for the rest are kept |
| a GitHub link, e.g. "scan https://github.com/owner/repo" | Scans that repo on the server (a GitHub session) |
| "stop" / "cancel the scan" | Stops the running scan (the **Stop** button next to the progress bar does the same) |
| "is my login code safe?" | When the agent only *thinks* a scan would help, it asks first: **Yes, scan** / **No** |
| anything else | The agent answers, using the findings and your code |

After you save a file that has findings, the assistant offers a rescan. If the LLM cannot be reached, simple scan commands ("scan", "rescan", a GitHub link, "stop") still work. Enter sends; Shift+Enter adds a new line.

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

*Vuln Scanner:* Set Token, Clear Token, Open Chat, New Session, Scan Workspace, Rescan, Cancel Scan. (Scan, Rescan and Cancel are also available here for keyboard users.)

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
