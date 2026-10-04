# Plan questions and the choices made

1. **Semgrep rule sets.** "General security rules" is read as the `p/default` pack. `p/security-audit` missed the planted SQL injection and MD5 cases. The image bakes `p/default` and `p/secrets`.
2. **Semgrep ignores `tests/` by default.** Semgrep always gets an explicit file list, so full and incremental scans cover the same files, test code included. The user's own `.semgrepignore` is therefore not honoured.
3. **Gitleaks has no file-list mode.** It scans the whole folder; results are then limited to the changed files.
4. **Gitleaks redaction vs. snippet masking.** With `--redact`, the secret value never reaches the harness. Snippets and LLM prompts mask the span at the columns the tools report: the first 4 characters, then asterisks. Only secrets that some tool detected can be masked.
5. **Merging only joins different tools.** Two Semgrep rules firing on the same line stay as two findings. The spec talks about "list all its tools", so merging is across tools only.
6. **Duplicate ids.** The same rule on two identical lines in one file would get the same id. The second one gets `hash(id + "#1")`, numbered in line order.
7. **Incremental scans and SonarQube.** The harness stores each tool's unmerged findings per scan (`raw/tool_findings.json`). A rescan combines these:
   - new Semgrep and Gitleaks results for changed files,
   - earlier Semgrep and Gitleaks results for unchanged files,
   - new SonarQube results for every file.

   Then it merges again. If a tool fails, its earlier results for unchanged files are kept.
8. **Rescan with nothing changed.** No scanner runs. The earlier findings are kept, and the progress message says so.
9. **Upload URL is claimed before the body is read.** A failed upload (400 or 413) uses up the URL, and the client asks for a new one. This avoids races between two uploads.
10. **Unpacking happens inside `start_scan`, not in the background.** That way a bad archive is an immediate tool error, and nothing is written to the code folder.
11. **Disk full during upload returns HTTP 507.** That code is not in the contract's table.
12. **Symlinks in GitHub repos are deleted after clone and fetch**, so no scanner can follow one out of the repo.
13. **Chat cannot start scans for any session type.** For GitHub sessions, the agent tells the user to send the link again or click Rescan.
14. **Tokens file is JSON**, so no YAML dependency is needed.
15. **Chat-driven scans (added later at the user's request).** `chat` first makes one routing LLM call that returns JSON (not a tool call, which small local models handle badly), then answers or returns an `action`. `start_scan` takes `paths` to scan only some folders; findings elsewhere are kept from the previous scan. Both are in the shared contract now.
16. **Merging also joins one tool's duplicates**, when they are on the same start line with the same CWE (several Semgrep rules often report one problem). This replaces choice 5.
