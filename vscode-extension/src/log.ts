// The extension's output channel. Never log tokens or file contents.

import * as vscode from "vscode";

let channel: vscode.LogOutputChannel | undefined;

export function initLog(): vscode.LogOutputChannel {
  channel ??= vscode.window.createOutputChannel("Vuln Scanner", { log: true });
  return channel;
}

export const log = {
  info: (msg: string) => channel?.info(msg),
  warn: (msg: string) => channel?.warn(msg),
  error: (msg: string) => channel?.error(msg),
};
