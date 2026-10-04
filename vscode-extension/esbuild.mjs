import * as esbuild from "esbuild";

const watch = process.argv.includes("--watch");
const builds = [
  { entryPoints: ["src/extension.ts"], outfile: "dist/extension.js", platform: "node", format: "cjs",
    external: ["vscode"], target: "node18" },
  { entryPoints: ["webview/main.ts"], outfile: "dist/webview.js", platform: "browser", format: "iife",
    target: "es2020" },
];
for (const b of builds) {
  const opts = { bundle: true, sourcemap: true, logLevel: "info", ...b };
  if (watch) await (await esbuild.context(opts)).watch();
  else await esbuild.build(opts);
}
