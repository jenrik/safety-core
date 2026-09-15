import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { evaluateConfiguredBash, initBashParser, setJudgeProvider, STRICT_BASH_PROFILE_EXECUTABLES, type BashConfiguredEvaluation, type BashConfiguredOptions, type BashProfileSnapshot } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-opencode-bash-guards-"));
let openCodeBashGuardBlockReason: typeof import("../adapters/opencode.ts")["openCodeBashGuardBlockReason"];
let createOpenCodePlugin: typeof import("../adapters/opencode.ts")["createOpenCodePlugin"];

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
  const adapter = await import("../adapters/opencode.ts");
  openCodeBashGuardBlockReason = adapter.openCodeBashGuardBlockReason;
  createOpenCodePlugin = adapter.createOpenCodePlugin;
});

afterAll(() => {
  setJudgeProvider(null);
  rmSync(wasmDir, { force: true, recursive: true });
});

describe("OpenCode single-pass Bash guards", () => {
  test("maps baseline policies to their existing OpenCode messages", () => {
    expect(openCodeBashGuardBlockReason(evaluate("cat credentials.json")))
      .toBe("Blocked by OpenCode safety policy: bash `cat` on 'credentials.json'");
    expect(openCodeBashGuardBlockReason(evaluate("curl https://api.github.com/user")))
      .toStartWith("Blocked: https://api.github.com/user");
    expect(openCodeBashGuardBlockReason(evaluate("kubectl view-secret application")))
      .toBe("Blocked by OpenCode safety policy: kubectl view-secret is blocked: it decodes and displays Secret values in plaintext.");
    expect(openCodeBashGuardBlockReason(evaluate("kubectl get Secret application"))).toBeNull();
    expect(openCodeBashGuardBlockReason(evaluate("unknown-command"))).toBeNull();
  });

  test("invokes the configured evaluator exactly once through the real callback", async () => {
    let calls = 0;
    const evaluate = (options: BashConfiguredOptions): BashConfiguredEvaluation => {
      calls++;
      expect(options).toMatchObject({
        source: "cat README.md",
        initialEnvironment: { kind: "unavailable" },
      });
      return evaluateConfiguredBash(options);
    };

    const plugin = await createOpenCodePlugin({ evaluateConfiguredBash: evaluate });
    const before = plugin["tool.execute.before"] as Function;
    await expect(before(bashInput("session-1", "call-1"), bashOutput("cat README.md"))).resolves.toBeUndefined();
    expect(calls).toBe(1);
  });

  test("the real before-execution callback preserves blocks and kubectl judge review", async () => {
    const plugin = await createOpenCodePlugin();
    const before = plugin["tool.execute.before"] as Function;

    await expect(before(bashInput("session-1", "secret"), bashOutput("cat credentials.json")))
      .rejects.toThrow("Blocked by OpenCode safety policy: bash `cat`");
    await expect(before(bashInput("session-1", "github"), bashOutput("curl https://api.github.com/user")))
      .rejects.toThrow("Blocked: https://api.github.com/user");
    await expect(before(bashInput("session-1", "kubectl"), bashOutput("kubectl view-secret application")))
      .rejects.toThrow("Blocked by OpenCode safety policy: kubectl view-secret is blocked");

    let judgeCalls = 0;
    setJudgeProvider(async () => {
      judgeCalls++;
      return { safe: true, reasoning: "metadata-only Secret review" };
    });
    await expect(before(bashInput("session-1", "review"), bashOutput("kubectl get Secret application"))).resolves.toBeUndefined();
    expect(judgeCalls).toBe(1);
  });

  test("uses one evaluator for enabled ghPrCreate enforcement", async () => {
    const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-gh-pr-"));
    const previous = process.env.SAFETY_CORE_CONFIG_HOME;
    try {
      mkdirSync(join(configHome, "safety-core"));
      writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({
        ghPrCreate: { enabled: true, allowedRepositories: ["acme/widgets"], allowedOrganizations: [] },
      }));
      process.env.SAFETY_CORE_CONFIG_HOME = configHome;

      let calls = 0;
      const evaluate = (options: BashConfiguredOptions): BashConfiguredEvaluation => {
        calls++;
        return evaluateConfiguredBash(options);
      };
      const plugin = await createOpenCodePlugin({ evaluateConfiguredBash: evaluate });
      const before = plugin["tool.execute.before"] as Function;

      await expect(before(bashInput("session-1", "pr"), bashOutput("gh pr create --repo github.com/attacker/widgets --fill")))
        .rejects.toThrow("requested repository is not allowlisted");
      expect(calls).toBe(1);
    } finally {
      if (previous === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
      else process.env.SAFETY_CORE_CONFIG_HOME = previous;
      rmSync(configHome, { force: true, recursive: true });
    }
  });

  test("reuses only an exact current-event result for permission and audit", async () => {
    const stateHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-state-"));
    const previousStateHome = process.env.XDG_STATE_HOME;
    const replies: unknown[] = [];
    let calls = 0;
    try {
      process.env.XDG_STATE_HOME = stateHome;
      const plugin = await createOpenCodePlugin({
        evaluateConfiguredBash(options: BashConfiguredOptions) {
          calls++;
          return evaluateConfiguredBash(options);
        },
      }, {
        permission: { reply: async (reply: unknown) => { replies.push(reply); } },
      } as never, "/workspace");
      const before = plugin["tool.execute.before"] as Function;
      const after = plugin["tool.execute.after"] as Function;
      const event = plugin.event as Function;
      const command = "kubectl get Secret application";
      setJudgeProvider(async () => ({ safe: true, reasoning: "metadata-only Secret review" }));

      await before(bashInput("session-1", "call-1"), bashOutput(command));
      await event({ event: {
        type: "permission.asked",
        properties: { id: "request-1", sessionID: "session-1", permission: "bash", patterns: [command], tool: { messageID: "message-1", callID: "call-1" } },
      } });
      await after(afterInput("session-1", "call-1", command), { output: "" });

      expect(calls).toBe(1);
      expect(replies).toEqual([]);
      const audit = JSON.parse(readFileSync(join(stateHome, "opencode", "kubectl-secret-audit.jsonl"), "utf8"));
      expect(audit).toMatchObject({ kubectl_subcommand: "get", resource: "secret", command_length: command.length });
    } finally {
      if (previousStateHome === undefined) delete process.env.XDG_STATE_HOME;
      else process.env.XDG_STATE_HOME = previousStateHome;
      rmSync(stateHome, { force: true, recursive: true });
    }
  });

  test("does not reuse a configured permission decision after profiles change", async () => {
    const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-config-"));
    const previousConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
    const replies: unknown[] = [];
    let calls = 0;
    try {
      mkdirSync(join(configHome, "safety-core"));
      process.env.SAFETY_CORE_CONFIG_HOME = configHome;
      writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghReadOnly: true }));
      const plugin = await createOpenCodePlugin({
        evaluateConfiguredBash(options: BashConfiguredOptions) {
          calls++;
          return evaluateConfiguredBash(options);
        },
      }, {
        permission: { reply: async (reply: unknown) => { replies.push(reply); } },
      } as never, "/workspace");
      const before = plugin["tool.execute.before"] as Function;
      const event = plugin.event as Function;
      const command = "gh label list";

      await before(bashInput("session-1", "call-1"), bashOutput(command));
      writeFileSync(join(configHome, "safety-core", "profiles.json"), "{}");
      await event({ event: {
        type: "permission.asked",
        properties: { id: "request-1", sessionID: "session-1", permission: "bash", patterns: [command], tool: { messageID: "message-1", callID: "call-1" } },
      } });

      expect(calls).toBe(2);
      expect(replies).toEqual([]);
    } finally {
      if (previousConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
      else process.env.SAFETY_CORE_CONFIG_HOME = previousConfigHome;
      rmSync(configHome, { force: true, recursive: true });
    }
  });

  test("property: audit cache reuse requires matching session, call, and source", async () => {
    let calls = 0;
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        calls++;
        return evaluateConfiguredBash(options);
      },
    });
    const before = plugin["tool.execute.before"] as Function;
    const command = "gh label list";
    const after = plugin["tool.execute.after"] as Function;
    await before(bashInput("session-a", "call-a"), bashOutput(command));
    await after(afterInput("session-a", "call-b", command), { output: "" });
    await before(bashInput("session-a", "call-a"), bashOutput(command));
    await after(afterInput("session-b", "call-a", command), { output: "" });
    await before(bashInput("session-a", "call-a"), bashOutput(command));
    await after(afterInput("session-a", "call-a", "gh repo list"), { output: "" });
    await before(bashInput("session-a", "call-a"), bashOutput(command));
    await after(afterInput("session-a", "call-a", command), { output: "" });
    expect(calls).toBe(7);
  });
});

function evaluate(source: string) {
  return evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot: defaultSnapshot });
}

const defaultSnapshot: BashProfileSnapshot = Object.freeze({
  readOnlyBash: false,
  ghApiReadOnly: false,
  ghReadOnly: false,
  helmReadOnly: false,
  strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
  ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
  limits: Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 }),
});

function bashInput(sessionID: string, callID: string) {
  return { tool: "bash", sessionID, callID };
}

function bashOutput(command: string) {
  return { args: { command } };
}

function afterInput(sessionID: string, callID: string, command: string) {
  return { tool: "bash", sessionID, callID, args: { command } };
}
