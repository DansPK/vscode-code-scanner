// The chat panel: a webview view in the sidebar. It only talks to the extension, never to the harness.

import { randomBytes } from "crypto";
import * as vscode from "vscode";
import type { Controller, View } from "./controller";
import type { ToExtension, ToWebview } from "./shared/messages";

export class ChatViewProvider implements vscode.WebviewViewProvider, View {
  static readonly id = "vulnScanner.chat";
  private view?: vscode.WebviewView;
  private ready = false;
  private queue: ToWebview[] = [];

  constructor(private readonly extensionUri: vscode.Uri, private readonly controller: Controller) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    this.ready = false;
    view.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, "dist"), vscode.Uri.joinPath(this.extensionUri, "media")],
    };
    view.webview.html = this.html(view.webview);
    const sub = this.controller.attach(this);
    view.onDidDispose(() => {
      sub.dispose();
      this.view = undefined;
    });
    view.webview.onDidReceiveMessage((msg: ToExtension) => {
      if (msg.type === "ready") {
        this.ready = true;
        for (const m of this.queue.splice(0)) void view.webview.postMessage(m);
      }
      void this.controller.handle(msg);
    });
  }

  post(msg: ToWebview) {
    if (this.view && this.ready) void this.view.webview.postMessage(msg);
    else if (msg.type !== "progress") this.queue.push(msg);
  }

  private html(webview: vscode.Webview): string {
    const nonce = randomBytes(16).toString("base64");
    const script = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, "dist", "webview.js"));
    const style = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, "media", "webview.css"));
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" href="${style}">
<title>Vuln Scanner</title>
</head>
<body>
<div id="app"></div>
<script nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
  }
}
