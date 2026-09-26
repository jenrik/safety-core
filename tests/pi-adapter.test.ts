import { expect, mock, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPolicyRuntime, type BashPolicyEvaluation, type LoadedPolicyRuntime } from "../src/index.ts";

const renderedSettings: Array<{ items: any[]; onChange: (id: string, value: string) => unknown }> = [];
mock.module("@earendil-works/pi-coding-agent", () => ({
  createBashTool: () => ({ execute() {} }),
  getSettingsListTheme: () => ({}),
}));
mock.module("@earendil-works/pi-tui", () => ({
  Container: class { addChild() {}; render() { return []; }; invalidate() {} },
  Text: class {},
  SettingsList: class {
    items: any[];
    onChange: (id: string, value: string) => unknown;
    constructor(items: any[], _maxVisible: number, _theme: unknown, onChange: (id: string, value: string) => unknown) {
      this.items = items;
      this.onChange = onChange;
      renderedSettings.push(this);
    }
    handleInput() {}
  },
}));
mock.module("typebox", () => ({ Type: { Object: (value: unknown) => value, String: () => ({}), Optional: (value: unknown) => value, Number: () => ({}) } }));

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = { config: { bashAnalysis: limits, pi: { autoApprove: false } }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const deny: BashPolicyEvaluation = { decision: "deny", analysis: { complete: true }, events: [], traces: [{ source: { canonicalPath: "/p" }, layer: "guard", event: {} as never, decision: { kind: "deny", reason: [{ kind: "literal", value: "generic denial" }] } }] };
const defer: BashPolicyEvaluation = { decision: "defer", analysis: { complete: false }, events: [], traces: [] };

test("Pi blocks generic denial and prompts only generic defer", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, {
    runtime: Promise.resolve(runtime),
    evaluatePolicies: (_runtime, source) => source === "deny" ? deny : defer,
  });
  const denied = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "deny", input: { command: "deny" } }, { ui: { notify() {} } });
  expect(denied).toEqual({ block: true, reason: "generic denial" });
  const deferred = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "defer", input: { command: "defer" } }, { hasUI: true, signal: undefined, ui: { confirm: async () => false, notify() {} } });
  expect(deferred).toEqual({ block: true, reason: "Command requires policy approval" });
});

test("Pi supplies tool cwd and an explicit executable resolver", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  let context: { readonly cwd?: string; readonly executableFilesystem?: unknown } | undefined;
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, {
    runtime: Promise.resolve(runtime),
    evaluatePolicies: (_runtime, _source, value) => {
      context = value;
      return defer;
    },
  });
  await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "cwd", input: { command: "id" } }, { cwd: "/workspace", ui: { notify() {} } });
  expect(context).toMatchObject({ cwd: "/workspace", executableFilesystem: expect.any(Object) });
});

test("Pi supplies inherited environment values to a real DSL permission policy", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const root = mkdtempSync(join(tmpdir(), "safety-core-pi-environment-"));
  const home = join(root, "home");
  const policy = join(root, "environment.policy.json");
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(policy, JSON.stringify(environmentPermissionPolicy()));
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
  const loaded = await loadPolicyRuntime(root, { SAFETY_CORE_CONFIG_HOME: home });
  const previous = process.env.CANARY_INHERITED;
  try {
    process.env.CANARY_INHERITED = "exact-pi-inherited-value";
    const handlers = new Map<string, Function>();
    createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, { runtime: Promise.resolve(loaded) });
    await handlers.get("session_start")!({}, { cwd: root });
    await expect(handlers.get("tool_call")!({ toolName: "bash", toolCallId: "environment", input: { command: "printf canary" } }, { cwd: root, ui: { notify() {} } })).resolves.toBeUndefined();
  } finally {
    if (previous === undefined) delete process.env.CANARY_INHERITED; else process.env.CANARY_INHERITED = previous;
  }
});

test("Pi propagates policy startup failure and no active session can evaluate afterward", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  let evaluations = 0;
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, {
    runtime: Promise.reject(new Error("startup failure")),
    evaluatePolicies: () => { evaluations++; return defer; },
  });
  await expect(handlers.get("session_start")!({}, { cwd: "/project" })).rejects.toThrow("Safety policy failed: startup failure");
  const result = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "failed", input: { command: "id" } }, { ui: { notify() {} } });
  expect(result).toMatchObject({ block: true, reason: "Safety policy failed: startup failure" });
  expect(evaluations).toBe(0);
});

test("Pi persists poison after an evaluation exception without re-evaluating", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  let calls = 0;
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, {
    runtime: Promise.resolve(runtime),
    evaluatePolicies: () => { calls++; throw new Error("evaluation failure"); },
  });
  const context = { cwd: "/project", ui: { notify() {} } };
  const first = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "first", input: { command: "id" } }, context);
  const second = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "second", input: { command: "id" } }, context);
  expect(first).toEqual({ block: true, reason: "Safety policy failed: evaluation failure" });
  expect(second).toEqual({ block: true, reason: "Safety policy failed: evaluation failure" });
  expect(calls).toBe(1);
});

test("Pi loads its immutable runtime from the session project cwd", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const root = mkdtempSync(join(tmpdir(), "safety-core-pi-project-"));
  const home = join(root, "home");
  const project = join(root, "project");
  const policy = join(root, "allow.policy.mjs");
  const projectPolicy = join(project, "project.policy.json");
  mkdirSync(join(home, "safety-core"), { recursive: true });
  mkdirSync(join(project, ".safety-core"), { recursive: true });
  writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "all" }, bashAnalysis: limits }));
  writeFileSync(join(project, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: ["project.policy.json"] }));
  writeFileSync(projectPolicy, JSON.stringify({
    language: "safety-core/bash-policy-v1", layer: "permission", select: [{ kind: "invocation" }], registers: {}, start: "start",
    states: { start: { cases: [], default: { decision: "ignore" }, end: { decision: "allow", reason: ["project allow"] } } },
  }));
  const handlers = new Map<string, Function>();
  let loadedCwd: string | undefined;
  let loadedRuntime: LoadedPolicyRuntime | undefined;
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {}, registerCommand() {}, appendEntry() {} } as never, {
    loadRuntime: async (cwd) => { loadedCwd = cwd; return loadedRuntime = await loadPolicyRuntime(cwd, { SAFETY_CORE_CONFIG_HOME: home }); },
  });
  await handlers.get("session_start")!({}, { cwd: project });
  expect(loadedCwd).toBe(project);
  expect(loadedRuntime!.policySet.sources.map((source) => source.canonicalPath)).toContain(projectPolicy);
});

test("Pi settings put judge selection in a submenu and auto-approve only policy defers", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  const commands = new Map<string, { handler: Function }>();
  const entries: unknown[] = [];
  const notifications: Array<{ message: string; level: string }> = [];
  let reloads = 0;
  renderedSettings.length = 0;
  createPiExtension({
    on: (name: string, handler: Function) => handlers.set(name, handler),
    registerTool() {},
    registerCommand: (name: string, command: { handler: Function }) => commands.set(name, command),
    appendEntry: (type: string, data: unknown) => entries.push({ type: "custom", customType: type, data }),
  } as never, {
    runtime: Promise.resolve(runtime),
    loadRuntime: async () => {
      reloads++;
      return runtime;
    },
    evaluatePolicies: (_runtime, source) => source === "deny" ? deny : defer,
  });
  const context = {
    cwd: "/workspace",
    mode: "tui",
    hasUI: true,
    signal: undefined,
    ui: {
      custom: async (factory: Function) => factory({ requestRender() {} }, { fg: (_name: string, value: string) => value, bold: (value: string) => value }, {}, () => {}),
      notify: (message: string, level: string) => notifications.push({ message, level }),
      confirm: async () => { throw new Error("auto-approve must not prompt"); },
    },
    modelRegistry: { getAvailable: () => [], getAll: () => [] },
    sessionManager: { getBranch: () => entries },
  };
  await commands.get("safety-core")!.handler("", context);
  const root = renderedSettings[0]!;
  expect(root.items.map((item) => item.id)).toEqual(["auto-approve", "judge", "reload-policies"]);
  expect(root.items[1]!.submenu).toBeFunction();
  const judge = root.items[1]!.submenu("active model", () => {});
  expect((judge as { items: Array<{ id: string }> }).items.map((item) => item.id)).toEqual(["judge-model"]);

  await root.onChange("auto-approve", "enabled");
  expect(entries).toEqual([{
    type: "custom",
    customType: "safety-core-pi-settings",
    data: { autoApprove: true, judgeModel: null },
  }]);
  await expect(handlers.get("tool_call")!({ toolName: "bash", toolCallId: "defer", input: { command: "defer" } }, context)).resolves.toBeUndefined();
  await expect(handlers.get("tool_call")!({ toolName: "bash", toolCallId: "deny", input: { command: "deny" } }, context))
    .resolves.toEqual({ block: true, reason: "generic denial" });

  await root.onChange("reload-policies", "reload");
  expect(reloads).toBe(1);
  expect(notifications).toContainEqual({ message: "Safety policies reloaded", level: "info" });
});

test("Pi exposes policy reload only through its TUI settings command", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const commands = new Map<string, { handler: Function }>();
  const tools: string[] = [];
  let reloads = 0;
  createPiExtension({
    on() {},
    registerTool: (tool: { name: string }) => tools.push(tool.name),
    registerCommand: (name: string, command: { handler: Function }) => commands.set(name, command),
    appendEntry() {},
  } as never, {
    runtime: Promise.resolve(runtime),
    loadRuntime: async () => { reloads++; return runtime; },
  });

  expect(tools).toEqual(["bash"]);
  await commands.get("safety-core")!.handler("", { cwd: "/workspace", mode: "json", ui: { notify() {} } });
  expect(reloads).toBe(0);
});

test("property: Pi session settings use the latest valid branch entry across 1,024 histories", async () => {
  const { resolvePiSessionSettings } = await import("../adapters/pi.ts");
  for (let seed = 0; seed < 1_024; seed++) {
    const entries: unknown[] = [{ type: "custom", customType: "other", data: { autoApprove: true, judgeModel: "ignored" } }];
    let expected = { autoApprove: false, judgeModel: "configured/model" };
    for (let index = 0; index < 1 + (seed % 16); index++) {
      if ((seed + index) % 5 === 0) {
        entries.push({ type: "custom", customType: "safety-core-pi-settings", data: { autoApprove: "invalid", judgeModel: null } });
        continue;
      }
      expected = { autoApprove: (seed + index) % 2 === 0, judgeModel: (seed + index) % 3 === 0 ? undefined : `provider/model-${seed}-${index}` };
      entries.push({
        type: "custom",
        customType: "safety-core-pi-settings",
        data: { autoApprove: expected.autoApprove, judgeModel: expected.judgeModel ?? null },
      });
    }
    expect(resolvePiSessionSettings(entries, { autoApprove: false, judgeModel: "configured/model" }), `seed ${seed}`).toEqual(expected);
  }
});

function environmentPermissionPolicy(): Record<string, unknown> {
  return {
    language: "safety-core/bash-policy-v1",
    layer: "permission",
    select: [{ kind: "invocation" }],
    registers: {}, folds: {}, options: {}, fragments: {}, start: "start",
    states: {
      start: {
        cases: [{
          when: { call: "environmentIsKnown", args: [{ call: "environmentLookup", args: ["CANARY_INHERITED"] }] },
          action: { decision: "allow", reason: ["inherited environment canary"] },
        }],
        default: { decision: "defer" },
        end: { decision: "defer" },
      },
    },
  };
}
