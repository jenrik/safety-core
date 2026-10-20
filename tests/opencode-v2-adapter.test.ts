import { beforeAll, expect, mock, test } from "bun:test";
import { fileURLToPath } from "node:url";

import { createOpenCodePlugin } from "../adapters/opencode.ts";
import OpenCodeV2Plugin, {
  createOpenCodeV2Plugin,
  normalizeOpenCodeV2ToolName,
  registerOpenCodeV2ReloadCommand,
} from "../adapters/opencode-v2.ts";
import {
  type BashPolicyEvaluation,
  createPermissionPromptServer,
  initBundledBashParser,
  type LoadedPolicyRuntime,
  OPENCODE_POLICY_RELOAD_COMMAND,
} from "../src/index.ts";

// The real `redactOpenCodeToolResult` is exercised in opencode-redact.test.ts.
// Here we stub it so the `setup()` wiring can be verified without standing up
// the Python socket service. Pre-fix, `setup()` forwarded only `event` and this
// stub was never reached for a tool result.
const REDACT_TOKEN = "ghp_" + "A".repeat(36);
const redactCalls: Array<{ output: unknown; config: unknown }> = [];
mock.module(fileURLToPath(new URL("../src/redact/opencode.ts", import.meta.url)), () => ({
  redactOpenCodeToolResult: async (output: { title?: string; output?: string }, config: unknown) => {
    redactCalls.push({ output, config });
    if (typeof output.title === "string") output.title = output.title.replaceAll(REDACT_TOKEN, "<REDACTED>");
    if (typeof output.output === "string") output.output = output.output.replaceAll(REDACT_TOKEN, "<REDACTED>");
  },
}));

beforeAll(initBundledBashParser);

test("OpenCode v2 exports a native plugin definition", () => {
  expect(OpenCodeV2Plugin.id).toBe("safety-core");
  expect(OpenCodeV2Plugin.setup).toBeInstanceOf(Function);
});

test("OpenCode v2 setup registers native V2 hooks without a V1 hook map", async () => {
  const hooks = new Map<string, (event: any) => Promise<void>>();
  let command: { execute: (input: unknown) => Promise<void> } | undefined;
  const cleanup = await OpenCodeV2Plugin.setup({
    location: { directory: process.cwd() },
    agent: { list: async () => [] },
    session: { get: async () => ({}), context: async () => [] },
    command: {
      transform: async (callback) => {
        callback({ add: (definition) => (command = definition) });
        return { dispose: async () => {} };
      },
    },
    tool: {
      hook: async (name, callback) => {
        hooks.set(`tool.${name}`, callback);
      },
    },
    permission: {
      hook: async (name, callback) => {
        hooks.set(`permission.${name}`, callback);
      },
    },
    event: { subscribe: async function* () {} },
  });

  expect([...hooks.keys()].sort()).toEqual(["permission.evaluate", "tool.execute.after", "tool.execute.before"]);
  await expect(
    hooks.get("tool.execute.before")!({ tool: "read", sessionID: "s", id: "c", input: { path: ".env" } }),
  ).rejects.toThrow("Blocked by safety policy");
  await command!.execute({ untrusted: true });
  await cleanup!();
});

test("OpenCode v2 setup forwards the tool result output into redaction", async () => {
  redactCalls.length = 0;
  const hooks = new Map<string, (event: any, output?: any) => Promise<void>>();
  const cleanup = await OpenCodeV2Plugin.setup({
    location: { directory: process.cwd() },
    agent: { list: async () => [] },
    session: { get: async () => ({}), context: async () => [] },
    command: {
      transform: async (callback) => {
        callback({ add: () => {} });
        return { dispose: async () => {} };
      },
    },
    tool: {
      hook: async (name, callback) => {
        hooks.set(`tool.${name}`, callback);
      },
    },
    permission: {
      hook: async (name, callback) => {
        hooks.set(`permission.${name}`, callback);
      },
    },
    event: { subscribe: async function* () {} },
  });

  const output = {
    title: `title ${REDACT_TOKEN}`,
    output: `output ${REDACT_TOKEN}`,
    metadata: { token: REDACT_TOKEN },
  };
  await hooks.get("tool.execute.after")!({ tool: "read", sessionID: "s", id: "c", input: {} }, output);

  expect(redactCalls).toHaveLength(1);
  expect(redactCalls[0]!.output).toBe(output);
  expect(output.output).toBe("output <REDACTED>");
  await cleanup!();
});

test("property: OpenCode v2 maps only the shell tool to the legacy bash policy across 1,024 names", () => {
  for (let seed = 0; seed < 1_024; seed++) {
    const tool = seed % 7 === 0 ? "shell" : `tool-${seed.toString(36)}`;
    expect(normalizeOpenCodeV2ToolName(tool), `seed ${seed}`).toBe(tool === "shell" ? "bash" : tool);
  }
});

test("OpenCode v2 registers the policy reload command", async () => {
  let registered: { name: string; description?: string; execute: (input: unknown) => Promise<void> } | undefined;
  let disposed = false;
  let reloads = 0;
  const registration = await registerOpenCodeV2ReloadCommand(
    {
      transform: async (callback) => {
        callback({ add: (command) => (registered = command) });
        return {
          dispose: async () => {
            disposed = true;
          },
        };
      },
    },
    async () => {
      reloads++;
    },
  );

  expect(registered).toMatchObject({
    name: OPENCODE_POLICY_RELOAD_COMMAND,
    description: "Reload safety-core policies",
  });
  await registered!.execute({});
  expect(reloads).toBe(1);
  await registration.dispose();
  expect(disposed).toBe(true);
});

test("property: OpenCode v2 reload command ignores all 1,024 invocation payloads", async () => {
  let execute: ((input: unknown) => Promise<void>) | undefined;
  let reloads = 0;
  await registerOpenCodeV2ReloadCommand(
    {
      transform: async (callback) => {
        callback({ add: (command) => (execute = command.execute) });
        return { dispose: async () => {} };
      },
    },
    async () => {
      reloads++;
    },
  );

  for (let seed = 0; seed < 1_024; seed++) {
    await execute!({ seed, text: `untrusted-${seed}` });
    expect(reloads, `seed ${seed}`).toBe(seed + 1);
  }
});

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

test("OpenCode forwards nested deferred Bash permission to the root prompt socket", async () => {
  const previous = process.env.SAFETY_CORE_PROMPT_SOCKET;
  const previousRootPID = process.env.SAFETY_CORE_PROMPT_ROOT_PID;
  const prompts: string[] = [];
  const server = await createPermissionPromptServer(async (request) => {
    prompts.push(request.message);
    return true;
  });
  process.env.SAFETY_CORE_PROMPT_SOCKET = server.path;
  process.env.SAFETY_CORE_PROMPT_ROOT_PID = "nested-root";
  try {
    for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
      const plugin = await create({ runtime, evaluatePolicies: () => defer });
      const output: { status: "allow" | "ask" | "deny" } = { status: "ask" };
      const identity = { sessionID: "nested", callID: create.name };
      await (plugin["tool.execute.before"] as Function)(
        { tool: "bash", ...identity },
        { args: { command: `nested-${create.name}` } },
      );
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "nested", ...identity }, output);
      expect(output.status).toBe("allow");
    }
    expect(prompts).toEqual([
      expect.stringContaining("nested-createOpenCodePlugin"),
      expect.stringContaining("nested-createOpenCodeV2Plugin"),
    ]);
  } finally {
    if (previous === undefined) delete process.env.SAFETY_CORE_PROMPT_SOCKET;
    else process.env.SAFETY_CORE_PROMPT_SOCKET = previous;
    if (previousRootPID === undefined) delete process.env.SAFETY_CORE_PROMPT_ROOT_PID;
    else process.env.SAFETY_CORE_PROMPT_ROOT_PID = previousRootPID;
    await server.close();
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
    // V2 has no V1 TUI-toast client. Reload state is still applied directly,
    // while the V1 adapter keeps its legacy toast behavior.
    if (create === createOpenCodePlugin)
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
    else expect(toasts).toEqual([]);
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
