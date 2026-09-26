import { expect, test } from "bun:test";

import { createOpenCodePlugin } from "../adapters/opencode.ts";
import { createOpenCodeV2Plugin } from "../adapters/opencode-v2.ts";
import type { BashPolicyEvaluation, LoadedPolicyRuntime } from "../src/index.ts";

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = { config: { bashAnalysis: limits }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const allow: BashPolicyEvaluation = { decision: "allow", analysis: { complete: true }, events: [], traces: [] };
const deny: BashPolicyEvaluation = { decision: "deny", analysis: { complete: true }, events: [], traces: [] };
const defer: BashPolicyEvaluation = { decision: "defer", analysis: { complete: false }, events: [], traces: [] };

test("OpenCode v2 maps Bash permission outcomes through its dedicated adapter", async () => {
  const plugin = await createOpenCodeV2Plugin({
    runtime,
    evaluatePolicies: (_runtime, source) => source === "allow" ? allow : source === "deny" ? deny : defer,
  });

  for (const [source, expected] of [["allow", "allow"], ["deny", "deny"], ["defer", "ask"]] as const) {
    const output = { status: "ask" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: source }, output);
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
    await (v1["permission.ask"] as Function)({ type: "bash", pattern: source }, v1Output);
    await (v2["permission.ask"] as Function)({ type: "bash", pattern: source }, v2Output);
    expect(v2Output.status, `seed ${seed}`).toBe(v1Output.status);
  }
});
