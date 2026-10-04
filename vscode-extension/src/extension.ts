import * as vscode from "vscode";
import { ChatViewProvider } from "./chatView";
import { Controller } from "./controller";
import { initLog } from "./log";

export function activate(ctx: vscode.ExtensionContext) {
  ctx.subscriptions.push(initLog());
  const controller = new Controller(ctx);
  const provider = new ChatViewProvider(ctx.extensionUri, controller);
  const run = (fn: () => Promise<unknown>) => () => fn().catch((e) => controller.showError(e));
  const openChat = () => vscode.commands.executeCommand("vulnScanner.chat.focus");

  ctx.subscriptions.push(
    controller,
    vscode.window.registerWebviewViewProvider(ChatViewProvider.id, provider, {
      webviewOptions: { retainContextWhenHidden: true },
    }),
    vscode.commands.registerCommand("vulnScanner.setToken", run(async () => {
      const token = await vscode.window.showInputBox({
        title: "Vuln Scanner token", prompt: "Paste the token you got from the scanner server's admin.",
        password: true, ignoreFocusOut: true,
      });
      if (token?.trim()) await controller.setToken(token.trim());
    })),
    vscode.commands.registerCommand("vulnScanner.clearToken", run(() => controller.clearToken())),
    vscode.commands.registerCommand("vulnScanner.openChat", openChat),
    vscode.commands.registerCommand("vulnScanner.newSession", run(async () => {
      await openChat();
      await controller.newSession();
    })),
    vscode.commands.registerCommand("vulnScanner.scanWorkspace", run(async () => {
      await openChat();
      await controller.scanWorkspace();
    })),
    vscode.commands.registerCommand("vulnScanner.rescan", run(async () => {
      await openChat();
      await controller.rescan();
    })),
    vscode.commands.registerCommand("vulnScanner.cancelScan", run(() => controller.cancelScan())),
    vscode.commands.registerCommand("vulnScanner.reconnect", run(() => controller.connect())),
    vscode.commands.registerCommand("vulnScanner.openSettings",
      () => vscode.commands.executeCommand("workbench.action.openSettings", "vulnScanner.serverUrl")),
    // vscode://local.vuln-scanner/set-token?token=... lets a setup script hand over a token.
    // Always ask first, so a web page cannot swap the token silently.
    vscode.window.registerUriHandler({
      handleUri: (uri) => void run(async () => {
        if (uri.path !== "/set-token") return;
        const token = new URLSearchParams(uri.query).get("token")?.trim();
        if (!token) return;
        const ok = await vscode.window.showWarningMessage(
          "Save the Vuln Scanner token from this link? Only do this if you started the setup yourself.",
          { modal: true }, "Save Token");
        if (ok === "Save Token") {
          await controller.setToken(token);
          await openChat();
        }
      })(),
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => controller.onSaved(doc.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => void controller.onSettingsChanged(e).catch((err) => controller.showError(err))),
  );

  void controller.connect();
  return { controller, context: ctx }; // used by the integration tests
}

export function deactivate() {}
