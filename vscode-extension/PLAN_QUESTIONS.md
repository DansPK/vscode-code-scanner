# Plan questions and the choices made

1. **Extra webview messages.** The spec's list is kept. Three small additions:
   - `thinking`, for the "Thinking..." line.
   - a `busy` flag in `state`, which disables Scan while files are hashed and uploaded.
   - `runCommand`, so the buttons in error messages (Set Token, Open Settings, Retry) can run a command.
2. **Rename and delete prompts.** `prompt()` and `confirm()` don't work in webviews. Rename uses an inline text box; delete asks with a modal VS Code dialog.
3. **A rescan with nothing changed** says "No files changed since the last scan" and starts nothing. The same goes for "Scan" when a previous scan exists. The spec allows a forced full rescan here, but no command asks for one, so none is offered.
4. **Which folder a session belongs to** is remembered in workspace state. A scan from another folder of a multi-root workspace creates a new session.
5. **Chatting before any session exists** creates a workspace session first.
6. **The scan summary in the chat** is shown locally and is not saved in the harness history (only `chat` calls are saved there).
7. **"Largest folders"** for an archive that is too large are grouped by the first two folder levels.
8. **Screenshots for the README** are not included yet; they need a real run against the harness.
9. **No Scan/Rescan buttons (changed later at the user's request).** The agent on the harness decides what each message wants, and returns an `action` in the `chat` reply (added to the shared contract). The extension still keeps the keyword rules from Milestone 3, used only when the LLM cannot be reached. Scan, Rescan and Cancel stay as commands; a Stop button shows while a scan runs. Later, also at the user's request: a **Rescan** button next to the tabs replaces the chat offer to rescan after saving, and each finished scan shows the harness's short summary (`summarize_findings`) instead of the plain counts.
10. **Auto-fix (added later at the user's request).** One `fix_findings` call runs the harness's fix agent, with its progress in a notification and the progress bar; afterwards the chat shows the agent's summary and a status per finding. All fixes for one file are shown together as one `vscode.diff`, with **Apply fix** / **Skip** in the chat. With several files the user picks **Apply all** (no diffs) or **Review one by one** (one diff at a time, the next after each answer). Applying replaces the document text in one undoable edit and saves it, so the usual "rescan?" offer follows. A file with unsaved changes, or whose hash differs from the proposal's `file_sha256`, is not touched. Overlapping edits from different fixes keep the first.
