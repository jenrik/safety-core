import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

async function build(entrypoint: string, outdir: string, external: readonly string[] = []): Promise<void> {
  const result = await Bun.build({
    entrypoints: [resolve(root, entrypoint)],
    outdir: resolve(root, outdir),
    naming: "[name].js",
    target: "node",
    format: "esm",
    external: [...external],
  });
  if (!result.success) {
    throw new Error(result.logs.map((log) => log.message).join("\n"));
  }
}

for (const packageName of ["core", "opencode-v1"]) {
  rmSync(resolve(root, "packages", packageName, "dist"), { force: true, recursive: true });
  mkdirSync(resolve(root, "packages", packageName, "dist"), { recursive: true });
}

await build("src/index.ts", "packages/core/dist", ["web-tree-sitter"]);
await build("src/cli.ts", "packages/core/dist", ["web-tree-sitter"]);
copyFileSync(resolve(root, "tree-sitter-bash.wasm"), resolve(root, "packages/core/tree-sitter-bash.wasm"));

await build("packages/opencode-v1/server.ts", "packages/opencode-v1/dist", ["@safety-core/core"]);
await build("packages/opencode-v1/tui.ts", "packages/opencode-v1/dist", ["@safety-core/core"]);
