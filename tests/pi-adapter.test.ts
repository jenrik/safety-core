import { expect, mock, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BashConfiguredOptions } from "../src/index.ts";

mock.module("@earendil-works/pi-coding-agent", () => ({ createBashTool: () => ({}) }));
mock.module("@earendil-works/pi-tui", () => ({ Container: class {}, Text: class {} }));
mock.module("typebox", () => ({ Type: { Object: (value: unknown) => value, String: (value: unknown) => value, Optional: (value: unknown) => value, Number: (value: unknown) => value } }));

test("Pi adapter blocks proven GH permission denials through its registered tool_call hook", async () => {
  const { initBashParser } = await import("../src/index.ts");
  const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-pi-adapter-"));
  const configHome = mkdtempSync(join(tmpdir(), "safety-core-pi-profile-"));
  const originalConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
  const runnerName = "SAFETY_CORE_TEST_RUNNER";
  const originalRunner = process.env[runnerName];
  const titleName = "SAFETY_CORE_TEST_TITLE";
  const originalTitle = process.env[titleName];
  try {
    mkdirSync(join(wasmDir, "node_modules"));
    copyFileSync(existsSync(join(process.cwd(), "tree-sitter-bash.wasm")) ? join(process.cwd(), "tree-sitter-bash.wasm") : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
    symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
    await initBashParser(wasmDir);
    mkdirSync(join(configHome, "safety-core"));
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghApiReadOnly: true, ghPrCreate: { enabled: true, allowedRepositories: [], allowedOrganizations: [] } }));
    process.env.SAFETY_CORE_CONFIG_HOME = configHome;
    process.env[runnerName] = "gh";
    process.env[titleName] = "x";

    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const adapter = (await import("../adapters/pi.ts")).default;
    adapter(pi as never);
    const result = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "test", input: { command: "gh pr create --repo github.com/attacker/widgets --fill" } }, { ui: { notify() {} } });
    expect(result).toMatchObject({ block: true });
    const apiResult = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "api-test", input: { command: "gh api user -X POST" } }, { ui: { notify() {} } });
    expect(apiResult).toMatchObject({ block: true });
    for (const command of [
      "builtin command cat credentials.json",
      "builtin command gh api user -X POST",
      "gh -X POST api user",
      "gh pr --title x create --body y --repo github.com/attacker/widgets",
      `gh pr -t "$${titleName}" create -b y -Rgithub.com/attacker/widgets`,
      "bash --rcfile credentials.json -ic true",
      "BASH_ENV=credentials.json bash -c true",
      "sudo BASH_ENV=credentials.json bash -c true",
      "strace --env=BASH_ENV=credentials.json bash -c true",
      "builtin builtin command cat credentials.json",
      "builtin builtin command gh api user -X POST",
      "curl -X POST https://API.GITHUB.COM/repos/acme/widgets/pulls",
      "strace -o trace.log gh api user -X POST",
      "bash ./create-pr.sh",
      "source ./create-pr.sh",
      `eval "$${runnerName}"`,
    ]) {
      const blocked = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: command, input: { command } }, { ui: { notify() {} } });
      expect(blocked, command).toMatchObject({ block: true });
    }
    const authCanary = "safety-core-auth-canary";
    const redacted = await handlers.get("tool_call")!(
      { toolName: "bash", toolCallId: "redacted-github-url", input: { command: `curl 'https://${authCanary}@API.GITHUB.COM/user?access_token=${authCanary}'` } },
      { ui: { notify() {} } },
    );
    expect(redacted).toMatchObject({ block: true });
    expect(JSON.stringify(redacted)).not.toContain(authCanary);
    let prompts = 0;
    const inheritedResult = await handlers.get("tool_call")!(
      { toolName: "bash", toolCallId: "inherited-test", input: { command: `$${runnerName} api user -X POST` } },
      { hasUI: true, ui: { confirm: async () => { prompts++; return false; }, notify() {} } },
    );
    expect(inheritedResult).toMatchObject({ block: true });
    expect(prompts).toBe(1);
    const startupResult = await handlers.get("tool_call")!(
      { toolName: "bash", toolCallId: "startup-test", input: { command: "bash --rcfile setup.sh -ic true" } },
      { hasUI: true, ui: { confirm: async () => { prompts++; return false; }, notify() {} } },
    );
    expect(startupResult).toMatchObject({ block: true });
    expect(prompts).toBe(2);
    const scriptResult = await handlers.get("tool_call")!(
      { toolName: "bash", toolCallId: "script-test", input: { command: "bash ./create-pr.sh" } },
      { hasUI: true, ui: { confirm: async () => { prompts++; return false; }, notify() {} } },
    );
    expect(scriptResult).toMatchObject({ block: true });
    expect(prompts).toBe(3);
  } finally {
    if (originalConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME; else process.env.SAFETY_CORE_CONFIG_HOME = originalConfigHome;
    if (originalRunner === undefined) delete process.env[runnerName]; else process.env[runnerName] = originalRunner;
    if (originalTitle === undefined) delete process.env[titleName]; else process.env[titleName] = originalTitle;
    rmSync(wasmDir, { force: true, recursive: true });
    rmSync(configHome, { force: true, recursive: true });
  }
});

test("Pi confirms opaque routes when only ghApiReadOnly is enabled", async () => {
  const { initBashParser } = await import("../src/index.ts");
  const wasmDir = await parserFixture();
  const configHome = mkdtempSync(join(tmpdir(), "safety-core-pi-api-profile-"));
  const originalConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
  try {
    await initBashParser(wasmDir);
    mkdirSync(join(configHome, "safety-core"));
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghApiReadOnly: true }));
    process.env.SAFETY_CORE_CONFIG_HOME = configHome;

    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const { createPiExtension } = await import("../adapters/pi.ts");
    createPiExtension(pi as never);
    let prompts = 0;
    const graphql = await handlers.get("tool_call")!(
      { toolName: "bash", toolCallId: "graphql", input: { command: "gh -XGET api /graphql" } },
      { hasUI: true, ui: { confirm: async () => { prompts++; return true; }, notify() {} } },
    );
    expect(graphql).toMatchObject({ block: true });
    expect(prompts).toBe(0);
    for (const command of ["gh create-issue", "gh extension exec mutate", "./create-pr.sh", "python ./create_pr.py"]) {
      const result = await handlers.get("tool_call")!(
        { toolName: "bash", toolCallId: command, input: { command } },
        { hasUI: true, ui: { confirm: async () => { prompts++; return false; }, notify() {} } },
      );
      expect(result, command).toMatchObject({ block: true, reason: "Command requires approval from an enabled safety profile" });
    }
    expect(prompts).toBe(4);
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
  const originalDebug = process.env.GH_DEBUG;
  const originalToken = process.env.GH_ENTERPRISE_TOKEN;
  try {
    await initBashParser(wasmDir);
    process.env.XDG_STATE_HOME = stateHome;
    process.env.GH_DEBUG = "policy-test";
    process.env.GH_ENTERPRISE_TOKEN = "excluded-policy-test-token";
    const handlers = new Map<string, Function>();
    const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
    const { createPiExtension } = await import("../adapters/pi.ts");
    let calls = 0;
    let environmentNames: string[] = [];
    createPiExtension(pi as never, {
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        calls++;
        environmentNames = options.initialEnvironment?.kind === "filtered" ? Object.keys(options.initialEnvironment.values) : [];
        return evaluateConfiguredBash(options);
      },
    });
    setJudgeProvider(async () => ({ safe: true, reasoning: "metadata-only Secret review", fromLLM: true }));
    const command = "kubectl get Secret application";
    const ctx = { signal: undefined, ui: { notify() {} } };

    await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "call-1", input: { command } }, ctx);
    await handlers.get("tool_result")!({ toolName: "bash", toolCallId: "call-1", input: { command }, content: "" }, ctx);

    expect(calls).toBe(1);
    expect(environmentNames).toContain("GH_DEBUG");
    expect(environmentNames).not.toContain("GH_ENTERPRISE_TOKEN");
    const audit = JSON.parse(readFileSync(join(stateHome, "pi", "kubectl-secret-audit.jsonl"), "utf8"));
    expect(audit).toMatchObject({ kubectl_subcommand: "get", resource: "secret", command_length: command.length });
  } finally {
    setJudgeProvider(null);
    if (originalStateHome === undefined) delete process.env.XDG_STATE_HOME; else process.env.XDG_STATE_HOME = originalStateHome;
    if (originalDebug === undefined) delete process.env.GH_DEBUG; else process.env.GH_DEBUG = originalDebug;
    if (originalToken === undefined) delete process.env.GH_ENTERPRISE_TOKEN; else process.env.GH_ENTERPRISE_TOKEN = originalToken;
    rmSync(wasmDir, { force: true, recursive: true });
    rmSync(stateHome, { force: true, recursive: true });
  }
});

test("Pi blocks a permission-only configured denial", async () => {
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
        audit: Object.freeze({ events: Object.freeze([]) }),
      }) as never;
    },
  });

  const result = await handlers.get("tool_call")!(
    { toolName: "bash", toolCallId: "call-2", input: { command: "docker rm image" } },
    { ui: { notify() {} } },
  );
  expect(result).toMatchObject({ block: true, reason: "permission-only test denial" });
});

test("Pi prompts for a deferred permission and fails closed without approval or on prompt failure", async () => {
  const handlers = new Map<string, Function>();
  const pi = { on: (name: string, handler: Function) => handlers.set(name, handler), registerCommand() {}, registerTool() {} };
  const { createPiExtension } = await import("../adapters/pi.ts");
  createPiExtension(pi as never, {
    evaluateConfiguredBash() {
      return Object.freeze({
        guards: Object.freeze({ kind: "pass", status: "indeterminate", policies: Object.freeze([]) }),
        permission: Object.freeze({ kind: "defer" }),
        profiles: Object.freeze({ ghApiReadOnly: Object.freeze({ kind: "defer" }) }),
        analysis: Object.freeze({ status: "indeterminate", failure: null, evidence: Object.freeze([]) }),
        audit: Object.freeze({ events: Object.freeze([]) }),
      }) as never;
    },
  });
  const approvals: Array<boolean | Error> = [true, false, new Error("prompt unavailable")];
  const prompts: string[] = [];
  const context = {
    hasUI: true,
    signal: undefined,
    ui: {
      confirm: async (title: string) => {
        prompts.push(title);
        const approval = approvals.shift()!;
        if (approval instanceof Error) throw approval;
        return approval;
      },
      notify() {},
    },
  };
  const toolCall = handlers.get("tool_call")!;

  await expect(toolCall({ toolName: "bash", toolCallId: "defer-approved", input: { command: "gh api user" } }, context)).resolves.toBeUndefined();
  await expect(toolCall({ toolName: "bash", toolCallId: "defer-rejected", input: { command: "gh api user" } }, context))
    .resolves.toMatchObject({ block: true, reason: "Command requires approval from an enabled safety profile" });
  await expect(toolCall({ toolName: "bash", toolCallId: "defer-error", input: { command: "gh api user" } }, context))
    .resolves.toMatchObject({ block: true, reason: "Command requires approval from an enabled safety profile" });
  expect(prompts).toEqual(["Safety permission required", "Safety permission required", "Safety permission required"]);
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
