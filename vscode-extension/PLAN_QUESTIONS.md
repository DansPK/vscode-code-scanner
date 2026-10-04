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
