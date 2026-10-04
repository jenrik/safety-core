import { beforeAll, expect, test } from "bun:test";

import { createOpenCodePlugin } from "../adapters/opencode.ts";
import { createOpenCodeV2Plugin } from "../adapters/opencode-v2.ts";
import {
  type BashPolicyEvaluation,
  initBundledBashParser,
  type LoadedPolicyRuntime,
  OPENCODE_POLICY_RELOAD_COMMAND,
} from "../src/index.ts";

beforeAll(initBundledBashParser);

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = {
  config: { bashAnalysis: limits },
  policySet: { policies: [], sources: [] },
  limits,
} as unknown as LoadedPolicyRuntime;
const allow: BashPolicyEvaluation = { decision: "allow", analysis: { complete: true }, events: [], traces: [] };
const deny: BashPolicyEvaluation = { decision: "deny", analysis: { complete: true }, events: [], traces: [] };
const defer: BashPolicyEvaluation = { decision: "defer", analysis: { complete: false }, events: [], traces: [] };

test("OpenCode v2 maps Bash permission outcomes through its dedicated adapter", async () => {
  const plugin = await createOpenCodeV2Plugin({
    runtime,
    evaluatePolicies: (_runtime, source) => (source === "allow" ? allow : source === "deny" ? deny : defer),
  });

  for (const [source, expected] of [
    ["allow", "allow"],
    ["deny", "deny"],
    ["defer", "ask"],
  ] as const) {
    const output = { status: "ask" };
    const identity = { sessionID: "session", callID: source };
    if (source === "deny") {
      await expect(
        (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: source } }),
      ).rejects.toThrow();
      continue;
    }
    await (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: source } });
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: source, ...identity }, output);
    expect(output.status).toBe(expected);
  }
});

test("property: OpenCode v2 preserves v1 permission behavior across 1,024 generated requests", async () => {
  const evaluatePolicies = (_runtime: LoadedPolicyRuntime, source: string) =>
    source === "allow" ? allow : source === "deny" ? deny : defer;
  const [v1, v2] = await Promise.all([
    createOpenCodePlugin({ runtime, evaluatePolicies }),
    createOpenCodeV2Plugin({ runtime, evaluatePolicies }),
  ]);

  for (let seed = 0; seed < 1_024; seed++) {
    const source = ["allow", "deny", "defer"][seed % 3]!;
    const v1Output = { status: "ask" };
    const v2Output = { status: "ask" };
    const identity = { sessionID: "session", callID: String(seed) };
    if (source === "deny") {
      await expect(
        (v1["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: source } }),
      ).rejects.toThrow();
      await expect(
        (v2["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: source } }),
      ).rejects.toThrow();
      continue;
    }
    for (const plugin of [v1, v2])
      await (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: source } });
    await (v1["permission.ask"] as Function)({ type: "bash", pattern: source, ...identity }, v1Output);
    await (v2["permission.ask"] as Function)({ type: "bash", pattern: source, ...identity }, v2Output);
    for (const plugin of [v1, v2]) await (plugin["tool.execute.after"] as Function)({ tool: "bash", ...identity }, {});
    expect(v2Output.status, `seed ${seed}`).toBe(v1Output.status);
  }
});

test("OpenCode reload action replaces the active runtime and keeps it on reload failure", async () => {
  const initial = { ...runtime, revision: 0 } as LoadedPolicyRuntime & { revision: number };
  const replacement = { ...runtime, revision: 1 } as LoadedPolicyRuntime & { revision: number };
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    let reloads = 0;
    const toasts: unknown[] = [];
    const plugin = await create(
      {
        runtime: initial,
        loadRuntime: async () => {
          reloads++;
          if (reloads === 2) throw new Error("invalid replacement");
          return replacement;
        },
        evaluatePolicies: (loaded) => ((loaded as typeof replacement).revision === 1 ? allow : deny),
      },
      {
        tui: {
          showToast: async (toast: unknown) => {
            toasts.push(toast);
          },
        },
      } as never,
    );
    const event = plugin.event as Function;

    const identity = { sessionID: "session", callID: "before" };
    await expect(
      (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: "id" } }),
    ).rejects.toThrow();

    await event({ event: { type: "tui.command.execute", properties: { command: OPENCODE_POLICY_RELOAD_COMMAND } } });
    const after = { status: "ask" };
    identity.callID = "after";
    await (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: "id" } });
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "id", ...identity }, after);
    expect(after.status).toBe("allow");

    await event({ event: { type: "tui.command.execute", properties: { command: OPENCODE_POLICY_RELOAD_COMMAND } } });
    const afterFailure = { status: "ask" };
    identity.callID = "after-failure";
    await (plugin["tool.execute.before"] as Function)({ tool: "bash", ...identity }, { args: { command: "id" } });
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "id", ...identity }, afterFailure);
    expect(afterFailure.status).toBe("allow");
    expect(toasts).toEqual([
      {
        query: { directory: process.cwd() },
        body: { title: "Safety policy reload", message: "Safety policies reloaded", variant: "success" },
      },
      {
        query: { directory: process.cwd() },
        body: {
          title: "Safety policy reload",
          message: "Safety policy reload failed: invalid replacement",
          variant: "error",
        },
      },
    ]);
  }
});

test("property: only the exact OpenCode TUI reload command invokes either adapter across 1,024 events", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    let reloads = 0;
    const plugin = await create({
      runtime,
      loadRuntime: async () => {
        reloads++;
        return runtime;
      },
    });
    const event = plugin.event as Function;
    for (let seed = 0; seed < 1_024; seed++) {
      const command = seed % 7 === 0 ? OPENCODE_POLICY_RELOAD_COMMAND : `agent-visible-command-${seed}`;
      await event({ event: { type: "tui.command.execute", properties: { command } } });
      expect(reloads, `seed ${seed}`).toBe(Math.floor(seed / 7) + 1);
    }
  }
});

test("OpenCode ignores agent command events that reuse the reload action name", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    let reloads = 0;
    const plugin = await create({
      runtime,
      loadRuntime: async () => {
        reloads++;
        return runtime;
      },
    });
    await (plugin.event as Function)({
      event: { type: "command.executed", properties: { command: OPENCODE_POLICY_RELOAD_COMMAND } },
    });
    expect(reloads).toBe(0);
  }
});
