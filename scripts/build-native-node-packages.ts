import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function build(
  entrypoint: string,
  outdir: string,
  external: readonly string[] = [],
  banner?: string,
): Promise<void> {
  const result = await Bun.build({
    entrypoints: [resolve(root, entrypoint)],
    outdir: resolve(root, outdir),
    naming: "[name].js",
    target: "node",
    format: "esm",
    external: [...external],
    banner,
  });
  if (!result.success) {
    throw new Error(result.logs.map((log) => log.message).join("\n"));
  }
}

for (const packageName of ["core", "opencode-v1", "pi", "claude-code"]) {
  rmSync(resolve(root, "packages", packageName, "dist"), { force: true, recursive: true });
  mkdirSync(resolve(root, "packages", packageName, "dist"), { recursive: true });
}

await build("src/index.ts", "packages/core/dist", ["web-tree-sitter"]);
await build("src/cli.ts", "packages/core/dist", ["web-tree-sitter"]);
copyFileSync(resolve(root, "tree-sitter-bash.wasm"), resolve(root, "packages/core/tree-sitter-bash.wasm"));

await build("packages/opencode-v1/server.ts", "packages/opencode-v1/dist", ["@safety-core/core"]);
await build("packages/opencode-v1/tui.ts", "packages/opencode-v1/dist", ["@safety-core/core"]);

await build("packages/pi/extension.ts", "packages/pi/extensions", [
  "@safety-core/core",
  "@earendil-works/pi-coding-agent",
  "@earendil-works/pi-ai",
  "@earendil-works/pi-tui",
  "typebox",
]);

for (const hook of [
  "bash_policy",
  "github_raw_redirect",
  "kubectl_secret_audit_log",
  "secret_command_reminder",
  "secrets_policy",
]) {
  await build(`adapters/claude-code/${hook}.ts`, "packages/claude-code/dist", ["@safety-core/core"], "#!/usr/bin/env node\n");
}
