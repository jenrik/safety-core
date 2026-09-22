import { expect, test } from "bun:test";
import { createOpenCodePlugin } from "../adapters/opencode.ts";
import type { BashPolicyEvaluation, LoadedPolicyRuntime } from "../src/index.ts";

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = { config: { bashAnalysis: limits }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const result = (decision: "allow" | "deny" | "defer"): BashPolicyEvaluation => ({ decision, analysis: { complete: decision !== "defer" }, events: [], traces: [] });

test("OpenCode keeps one immutable loaded policy set across permission callbacks", async () => {
  let loads = 0;
  const plugin = await createOpenCodePlugin({
    loadRuntime: async () => { loads++; return runtime; },
    evaluatePolicies: (_runtime, source) => result(source === "safe" ? "allow" : "defer"),
  });
  const output = { status: "ask" };
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "safe" }, output);
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "unknown" }, output);
  expect(loads).toBe(1);
  expect(output.status).toBe("allow");
});
