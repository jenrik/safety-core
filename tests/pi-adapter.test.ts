import { expect, mock, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BashConfiguredOptions } from "../src/index.ts";

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

test("Pi performs one configured evaluation and reuses its kubectl audit view", async () => {
  const { evaluateConfiguredBash, initBashParser, setJudgeProvider } = await import("../src/index.ts");
  const wasmDir = await parserFixture();
  const stateHome = mkdtempSync(join(tmpdir(), "safety-core-pi-state-"));
  const originalStateHome = process.env.XDG_STATE_HOME;
  try {
    await initBashParser(wasmDir);
    process.env.XDG_STATE_HOME = stateHome;
    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const { createPiExtension } = await import("../adapters/pi.ts");
    let calls = 0;
    createPiExtension(pi as never, {
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        calls++;
        return evaluateConfiguredBash(options);
      },
    });
    setJudgeProvider(async () => ({ safe: true, reasoning: "metadata-only Secret review", fromLLM: true }));
    const command = "kubectl get Secret application";
    const ctx = { signal: undefined, ui: { notify() {} } };

    await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "call-1", input: { command } }, ctx);
    await handlers.get("tool_result")!({ toolName: "bash", toolCallId: "call-1", input: { command }, content: "" }, ctx);

    expect(calls).toBe(1);
    const audit = JSON.parse(readFileSync(join(stateHome, "pi", "kubectl-secret-audit.jsonl"), "utf8"));
    expect(audit).toMatchObject({ kubectl_subcommand: "get", resource: "secret", command_length: command.length });
  } finally {
    setJudgeProvider(null);
    if (originalStateHome === undefined) delete process.env.XDG_STATE_HOME; else process.env.XDG_STATE_HOME = originalStateHome;
    rmSync(wasmDir, { force: true, recursive: true });
    rmSync(stateHome, { force: true, recursive: true });
  }
});

test("Pi never blocks a permission-only configured decision", async () => {
  const handlers = new Map<string, Function>();
  const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
  const { createPiExtension } = await import("../adapters/pi.ts");
  createPiExtension(pi as never, {
    evaluateConfiguredBash() {
      return Object.freeze({
        guards: Object.freeze({ kind: "pass", status: "complete", policies: Object.freeze([]) }),
        permission: Object.freeze({ kind: "deny", profile: "ghReadOnly", reason: "permission-only test denial" }),
        profiles: Object.freeze({ ghReadOnly: Object.freeze({ kind: "deny", profile: "ghReadOnly", reason: "permission-only test denial" }) }),
        analysis: Object.freeze({ status: "complete", evidence: Object.freeze([]) }),
        audit: Object.freeze({ policies: Object.freeze([]), kubectlSecret: null }),
      }) as never;
    },
  });

  const result = await handlers.get("tool_call")!(
    { toolName: "bash", toolCallId: "call-2", input: { command: "docker rm image" } },
    { ui: { notify() {} } },
  );
  expect(result).toBeUndefined();
});

test("property: supported guard wrappers still block Pi", async () => {
  const { initBashParser } = await import("../src/index.ts");
  const wasmDir = await parserFixture();
  try {
    await initBashParser(wasmDir);
    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const { createPiExtension } = await import("../adapters/pi.ts");
    createPiExtension(pi as never);
    const toolCall = handlers.get("tool_call")!;
    const violations = ["cat credentials.json", "curl https://api.github.com/user", "kubectl view-secret application"];
    const wrappers = [(command: string) => command, (command: string) => `env -i ${command}`, (command: string) => `strace -f ${command}`, (command: string) => `sh -c '${command}'`];
    for (const violation of violations) {
      for (const wrap of wrappers) {
        const result = await toolCall(
          { toolName: "bash", toolCallId: `${violation}-${wrappers.indexOf(wrap)}`, input: { command: wrap(violation) } },
          { ui: { notify() {} } },
        );
        expect(result, wrap(violation)).toMatchObject({ block: true });
      }
    }
  } finally {
    rmSync(wasmDir, { force: true, recursive: true });
  }
});

async function parserFixture(): Promise<string> {
  const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-pi-adapter-"));
  mkdirSync(join(wasmDir, "node_modules"));
  copyFileSync(existsSync(join(process.cwd(), "tree-sitter-bash.wasm")) ? join(process.cwd(), "tree-sitter-bash.wasm") : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  return wasmDir;
}
