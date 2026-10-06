# vscode-code-scanner

A self-hosted vulnerability scanner you drive from a chat panel in VS Code.

The scanning runs in Docker — Semgrep, Gitleaks and SonarQube Community Edition find issues, and a local LLM reviews each finding, explains it, and suggests a fix. The VS Code extension is the client: you tell it in plain language what to scan (your workspace, a folder, or a GitHub repo), watch progress live, and jump from a finding to the exact line in your code.

## Layout

- [`analyzer-agent-harness/`](analyzer-agent-harness/) — Python MCP server (the scanner harness). Runs in Docker, serves over HTTP or HTTPS, bearer-token auth. See its [README](analyzer-agent-harness/README.md).
- [`vscode-extension/`](vscode-extension/) — the VS Code extension (MCP client). See its [README](vscode-extension/README.md).

## Highlights

- **Chat-driven** — one Rescan button, everything else by chat; an agent decides what each message means (scan, rescan, scan a GitHub repo, cancel, or just answer) and asks first when unsure.
- **Many languages** — Semgrep rules for Python, Java, Kotlin, C#, JavaScript, TypeScript, React (JSX/TSX), Go, PHP, Ruby, and more, plus Terraform, Dockerfiles and Kubernetes. Includes custom SQL-injection rules.
- **Incremental** — a rescan uploads and scans only the files that changed; findings for the rest are kept.
- **Fix agent** — ask "fix all high findings", or click **Fix** or **Fix all**. A coding agent reads the code, edits what is needed (also other files, such as imports), reruns the scanners to confirm, and reports per finding. You see every change as a diff, and nothing is written until you apply it.
- **Summary** — after every scan, a short summary: counts, the most affected files, and up to three things to fix first. Ask "summarize" for it again.
- **Live results** — findings appear as each scanner finishes, and the LLM review fills in per finding.
- **Private** — the code and the LLM stay on your own infrastructure.

## Quick start

For the full walkthrough, including port conflicts, checking the LLM, packaging the extension and troubleshooting, see [SETUP.md](SETUP.md).

1. In `analyzer-agent-harness/`, copy `.env.example` to `.env`, fill it in, and run `docker compose up -d --build`. See the harness README for the SonarQube token and (optional) HTTPS setup.
2. Create a user token: `docker compose exec harness harness-token <your-name>`.
3. Install the extension, set `vulnScanner.serverUrl`, and paste the token with **Vuln Scanner: Set Token**.
4. Open the Vuln Scanner panel and type, for example, "scan this project".
