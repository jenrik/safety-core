import { expect, mock, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadPolicyRuntime, type BashPolicyEvaluation, type LoadedPolicyRuntime } from "../src/index.ts";

mock.module("@earendil-works/pi-coding-agent", () => ({ createBashTool: () => ({ execute() {} }) }));
mock.module("@earendil-works/pi-tui", () => ({ Container: class { addChild() {} }, Text: class {} }));
mock.module("typebox", () => ({ Type: { Object: (value: unknown) => value, String: () => ({}), Optional: (value: unknown) => value, Number: () => ({}) } }));

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = { config: { bashAnalysis: limits }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const deny: BashPolicyEvaluation = { decision: "deny", analysis: { complete: true }, events: [], traces: [{ source: { canonicalPath: "/p" }, layer: "guard", event: {} as never, decision: { kind: "deny", reason: [{ kind: "literal", value: "generic denial" }] } }] };
const defer: BashPolicyEvaluation = { decision: "defer", analysis: { complete: false }, events: [], traces: [] };

test("Pi blocks generic denial and prompts only generic defer", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
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
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
    runtime: Promise.resolve(runtime),
    evaluatePolicies: (_runtime, _source, value) => {
      context = value;
      return defer;
    },
  });
  await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "cwd", input: { command: "id" } }, { cwd: "/workspace", ui: { notify() {} } });
  expect(context).toMatchObject({ cwd: "/workspace", executableFilesystem: expect.any(Object) });
});

test("Pi poisons a session on runtime policy failure", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
    runtime: Promise.reject(new Error("startup failure")),
  });
  const result = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "failed", input: { command: "id" } }, { ui: { notify() {} } });
  expect(result).toMatchObject({ block: true, reason: "Safety policy failed: startup failure" });
});

test("Pi persists poison after an evaluation exception without re-evaluating", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  let calls = 0;
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
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
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
    loadRuntime: async (cwd) => { loadedCwd = cwd; return loadedRuntime = await loadPolicyRuntime(cwd, { SAFETY_CORE_CONFIG_HOME: home }); },
  });
  await handlers.get("session_start")!({}, { cwd: project });
  expect(loadedCwd).toBe(project);
  expect(loadedRuntime!.policySet.sources.map((source) => source.canonicalPath)).toContain(projectPolicy);
});
