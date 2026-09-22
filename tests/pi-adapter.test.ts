import { expect, mock, test } from "bun:test";
import type { BashPolicyEvaluation, LoadedPolicyRuntime } from "../src/index.ts";

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

test("Pi poisons a session on runtime policy failure", async () => {
  const { createPiExtension } = await import("../adapters/pi.ts");
  const handlers = new Map<string, Function>();
  createPiExtension({ on: (name: string, handler: Function) => handlers.set(name, handler), registerTool() {} } as never, {
    runtime: Promise.reject(new Error("startup failure")),
  });
  const result = await handlers.get("tool_call")!({ toolName: "bash", toolCallId: "failed", input: { command: "id" } }, { ui: { notify() {} } });
  expect(result).toMatchObject({ block: true, reason: "Safety policy failed: startup failure" });
});
