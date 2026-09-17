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

  test("blocks permission denials before execution without waiting for a native permission event", async () => {
    const denied = evaluateConfiguredBash({ source: "unknown-command", initialEnvironment: { kind: "unavailable" }, profileSnapshot: defaultSnapshot });
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash() {
        return {
          ...denied,
          permission: { kind: "deny", profile: "ghApiReadOnly", reason: "permission-only test denial" },
        };
      },
    });

    await expect((plugin["tool.execute.before"] as Function)(bashInput("session-1", "permission-deny"), bashOutput("gh api user -X POST")))
      .rejects.toThrow("Blocked by OpenCode safety policy: permission-only test denial");
  });

  test("invokes the configured evaluator exactly once through the real callback", async () => {
    let calls = 0;
    const evaluate = (options: BashConfiguredOptions): BashConfiguredEvaluation => {
      calls++;
      expect(options).toMatchObject({
        source: "cat README.md",
        initialEnvironment: { kind: "filtered" },
      });
      return evaluateConfiguredBash(options);
    };

    const plugin = await createOpenCodePlugin({ evaluateConfiguredBash: evaluate });
    const before = plugin["tool.execute.before"] as Function;
    await expect(before(bashInput("session-1", "call-1"), bashOutput("cat README.md"))).resolves.toBeUndefined();
    expect(calls).toBe(1);
  });

  test("notifies when analysis exhausts its budget but not for completed decisions", async () => {
    const notifications: unknown[] = [];
    const client = {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never;
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        return evaluateConfiguredBash({
          ...options,
          limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10_000 },
        });
      },
    }, client);
    const before = plugin["tool.execute.before"] as Function;

    await expect(before(bashInput("session-1", "budget"), bashOutput("gh label list"))).resolves.toBeUndefined();
    expect(notifications).toEqual([{
      body: {
        title: "Safety analysis incomplete",
        message: "Safety analysis reached its complexity limit. OpenCode will use its normal permission policy.",
        variant: "warning",
      },
    }]);

    notifications.length = 0;
    const completed = await createOpenCodePlugin({}, client);
    const completedBefore = completed["tool.execute.before"] as Function;
    await expect(completedBefore(bashInput("session-1", "allow"), bashOutput("gh label list"))).resolves.toBeUndefined();
    await expect(completedBefore(bashInput("session-1", "deny"), bashOutput("cat credentials.json"))).rejects.toThrow("Blocked by OpenCode safety policy");
    expect(notifications).toEqual([]);
  });

  test("notifies when evaluation throws without replacing the analysis error", async () => {
    const notifications: unknown[] = [];
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash() {
        throw new Error("parser unavailable");
      },
    }, {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;

    await expect(before(bashInput("session-1", "error"), bashOutput("gh label list"))).rejects.toThrow("parser unavailable");
    expect(notifications).toEqual([{
      body: {
        title: "Safety analysis incomplete",
        message: "Safety analysis could not be completed. OpenCode will use its normal permission policy.",
        variant: "warning",
      },
    }]);
  });

  test("notifies generic analysis failures and preserves errors when toast delivery fails", async () => {
    const failure = evaluateConfiguredBash({ source: "gh label list", initialEnvironment: { kind: "unavailable" }, profileSnapshot: defaultSnapshot });
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash() {
        return {
          ...failure,
          analysis: { ...failure.analysis, status: "failure", failure: { budget: null } },
        };
      },
    }, {
      tui: { showToast() { throw new Error("toast unavailable"); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;

    await expect(before(bashInput("session-1", "failure"), bashOutput("gh label list"))).resolves.toBeUndefined();

    const errorPlugin = await createOpenCodePlugin({
      evaluateConfiguredBash() {
        throw new Error("parser unavailable");
      },
    }, {
      tui: { showToast() { throw new Error("toast unavailable"); } },
    } as never);
    await expect((errorPlugin["tool.execute.before"] as Function)(bashInput("session-1", "error-toast"), bashOutput("gh label list")))
      .rejects.toThrow("parser unavailable");
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
        ghApiReadOnly: true,
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

      await expect(before(bashInput("session-1", "pr"), bashOutput("GH_PROMPT_DISABLED=1 gh pr create --repo github.com/attacker/widgets --fill")))
        .rejects.toThrow("requested repository is not allowlisted");
      await expect(before(bashInput("session-1", "api"), bashOutput("gh api user -X POST")))
        .rejects.toThrow("gh api --method POST is not read-only");
      expect(calls).toBe(2);
    } finally {
      if (previous === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
      else process.env.SAFETY_CORE_CONFIG_HOME = previous;
      rmSync(configHome, { force: true, recursive: true });
    }
  });

  test("leaves inherited executable variables at the native prompt", async () => {
    const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-filtered-env-"));
    const previousConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
    const name = "SAFETY_CORE_TEST_RUNNER";
    const previousRunner = process.env[name];
    try {
      mkdirSync(join(configHome, "safety-core"));
      writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghApiReadOnly: true }));
      process.env.SAFETY_CORE_CONFIG_HOME = configHome;
      process.env[name] = "gh";
      let permission: string | undefined;
      const plugin = await createOpenCodePlugin({
        evaluateConfiguredBash(options) {
          expect(options.initialEnvironment).toMatchObject({ kind: "filtered" });
          if (options.initialEnvironment?.kind === "filtered") expect(options.initialEnvironment.values[name]).toBeUndefined();
          const evaluation = evaluateConfiguredBash(options);
          permission = evaluation.permission.kind;
          return evaluation;
        },
      });
      const output = { status: "ask" };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: `$${name} api user -X POST` }, output);
      expect(permission).toBe("defer");
      expect(output.status).toBe("ask");
    } finally {
      if (previousConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME; else process.env.SAFETY_CORE_CONFIG_HOME = previousConfigHome;
      if (previousRunner === undefined) delete process.env[name]; else process.env[name] = previousRunner;
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

  test("notifies an analysis failure once when a profile reload requires permission re-analysis", async () => {
    const configHome = mkdtempSync(join(tmpdir(), "safety-core-opencode-analysis-notification-"));
    const previousConfigHome = process.env.SAFETY_CORE_CONFIG_HOME;
    const notifications: unknown[] = [];
    try {
      mkdirSync(join(configHome, "safety-core"));
      process.env.SAFETY_CORE_CONFIG_HOME = configHome;
      writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ bashAnalysis: { maxSteps: 1 } }));
      const plugin = await createOpenCodePlugin({}, {
        permission: { reply: async () => {} },
        tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
      } as never, "/workspace");
      const before = plugin["tool.execute.before"] as Function;
      const event = plugin.event as Function;
      const command = "gh label list";

      await before(bashInput("session-1", "call-1"), bashOutput(command));
      writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ bashAnalysis: { maxSteps: 1 }, ghReadOnly: true }));
      await event({ event: {
        type: "permission.asked",
        properties: { id: "request-1", sessionID: "session-1", permission: "bash", patterns: [command], tool: { callID: "call-1" } },
      } });

      expect(notifications).toHaveLength(1);
    } finally {
      if (previousConfigHome === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME;
      else process.env.SAFETY_CORE_CONFIG_HOME = previousConfigHome;
      rmSync(configHome, { force: true, recursive: true });
    }
  });

  test("notifies an analysis failure once across legacy before and permission callbacks", async () => {
    const notifications: unknown[] = [];
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        return evaluateConfiguredBash({
          ...options,
          limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10_000 },
        });
      },
    }, {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;
    const permission = plugin["permission.ask"] as Function;
    const command = "gh label list";

    await before(bashInput("session-1", "call-1"), bashOutput(command));
    await permission({ type: "bash", sessionID: "session-1", pattern: command }, { status: "ask" });

    expect(notifications).toHaveLength(1);
  });

  test("does not suppress a later legacy notification after before aborts", async () => {
    const notifications: unknown[] = [];
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash() {
        throw new Error("parser unavailable");
      },
    }, {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;
    const permission = plugin["permission.ask"] as Function;
    const command = "gh label list";

    await expect(before(bashInput("session-1", "aborted"), bashOutput(command))).rejects.toThrow("parser unavailable");
    await expect(permission({ type: "bash", sessionID: "session-1", pattern: command }, { status: "ask" })).rejects.toThrow("parser unavailable");

    expect(notifications).toHaveLength(2);
  });

  test("clears the legacy notification association after a completed lifecycle", async () => {
    const notifications: unknown[] = [];
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        return evaluateConfiguredBash({
          ...options,
          limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10_000 },
        });
      },
    }, {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;
    const after = plugin["tool.execute.after"] as Function;
    const permission = plugin["permission.ask"] as Function;
    const command = "gh label list";

    await before(bashInput("session-1", "completed"), bashOutput(command));
    await after(afterInput("session-1", "completed", command), { output: "" });
    await permission({ type: "bash", sessionID: "session-1", pattern: command }, { status: "ask" });

    expect(notifications).toHaveLength(2);
  });

  test("bounds analysis-failure notification tracking", async () => {
    const notifications: unknown[] = [];
    const plugin = await createOpenCodePlugin({
      evaluateConfiguredBash(options: BashConfiguredOptions) {
        return evaluateConfiguredBash({
          ...options,
          limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10_000 },
        });
      },
    }, {
      tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
    } as never);
    const before = plugin["tool.execute.before"] as Function;

    for (let index = 0; index <= 128; index++) {
      await before(bashInput("session-1", `call-${index}`), bashOutput("gh label list"));
    }
    await before(bashInput("session-1", "call-0"), bashOutput("gh label list"));

    expect(notifications).toHaveLength(130);
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

  test("property: completed allow, deny, and neutral analyses never notify", async () => {
    for (const source of ["gh label list", "cat credentials.json", "UNKNOWN=$COMMAND; $UNKNOWN"]) {
      const notifications: unknown[] = [];
      const plugin = await createOpenCodePlugin({}, {
        tui: { showToast: async (notification: unknown) => { notifications.push(notification); } },
      } as never);
      const before = plugin["tool.execute.before"] as Function;

      await before(bashInput("session-1", source), bashOutput(source)).catch(() => {});
      expect(notifications).toEqual([]);
    }
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
