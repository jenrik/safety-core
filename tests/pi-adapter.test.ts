import { expect, mock, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("@earendil-works/pi-coding-agent", () => ({ createBashTool: () => ({}) }));
mock.module("@earendil-works/pi-tui", () => ({ Container: class {}, Text: class {} }));
mock.module("typebox", () => ({ Type: { Object: (value: unknown) => value, String: (value: unknown) => value, Optional: (value: unknown) => value, Number: (value: unknown) => value } }));

test("Pi adapter blocks a proven ghPrCreate denial through its registered tool_call hook", async () => {
  const { initBashParser } = await import("../src/index.ts");
  const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-pi-adapter-"));
  const configHome = mkdtempSync(join(tmpdir(), "safety-core-pi-profile-"));
  const originalConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
  try {
    mkdirSync(join(wasmDir, "node_modules"));
    copyFileSync(existsSync(join(process.cwd(), "tree-sitter-bash.wasm")) ? join(process.cwd(), "tree-sitter-bash.wasm") : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
    symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
    await initBashParser(wasmDir);
    mkdirSync(join(configHome, "safety-core"));
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghPrCreate: { enabled: true, allowedRepositories: [], allowedOrganizations: [] } }));
    process.env.SAFETY_CORE_CONFIG_HOME = configHome;

    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const adapter = (await import("../adapters/pi.ts")).default;
    adapter(pi as never);
    const result = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "test", input: { command: "gh pr create --repo github.com/attacker/widgets --fill" } }, { ui: { notify() {} } });
    expect(result).toMatchObject({ block: true });
  } finally {
    if (originalConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME; else process.env.SAFETY_CORE_CONFIG_HOME = originalConfigHome;
    rmSync(wasmDir, { force: true, recursive: true });
    rmSync(configHome, { force: true, recursive: true });
  }
});
