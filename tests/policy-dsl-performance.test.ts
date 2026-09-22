import { expect, test } from "bun:test";

import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { validatePolicyDocument } from "../src/policy/dsl/validate.ts";

test("property: generated finite machines halt within their token-and-byte consumption bound", () => {
  for (let seed = 0; seed < 128; seed++) {
    const document: Record<string, any> = {
      language: "safety-core/bash-policy-v1", layer: "permission", select: [{ kind: "invocation" }],
      registers: { count: { type: "count", max: 128, initial: 0 } },
      options: { flag: { names: ["-f"], value: "absent", forms: [], availableIn: "*", set: { count: 1 } } },
      start: "scan",
      states: { scan: { cases: [{ when: true, action: { consume: "word", next: "scan", set: { count: { ref: "count" } } } }], default: { decision: "ignore" }, end: { decision: "allow", reason: ["ok"] } } },
    };
    const program = compilePolicyDocument(validatePolicyDocument(document));
    const policy = createDslPolicy(program, "/policy/generated.policy.json") as any;
    const argv = Array.from({ length: seed % 64 }, (_, index) => ({ kind: "known" as const, value: index % 7 === 0 ? "-f" : `word-${index}` }));
    const result = policy.evaluateWithTrace({ kind: "invocation", executable: null, executableIdentity: { qualification: "unknown", reason: "unresolved-spelling" }, argv, environment: {}, missingBindings: "unset", redirects: [], assignments: {}, span: { start: 0, end: 0 }, provenance: { route: ["direct"] }, inPipeline: false, processEffect: "none" });
    const bound = argv.length + argv.reduce((bytes, word) => bytes + word.value.length, 0) + 1;
    expect(result.steps.length, `seed ${seed}`).toBeLessThanOrEqual(bound);
    expect(result.steps.length).toBeLessThanOrEqual(argv.length + 1);
  }
});

test("practical P/B matrix keeps steps, working declarations, and trace output linear in consumed input", () => {
  for (const optionCount of [1, 8, 32, 64]) {
    for (const clusterBytes of [16, 64, 256, 1_024]) {
      const options: Record<string, unknown> = Object.fromEntries(Array.from({ length: optionCount - 1 }, (_, index) => [
        `long${index}`, { names: [`--long-${index}`], value: "absent", forms: [], availableIn: "*" },
      ]));
      options.cluster = { names: ["-v"], value: "absent", forms: [], availableIn: "*" };
      const document = {
        language: "safety-core/bash-policy-v1", layer: "permission", select: [{ kind: "invocation" }], registers: {}, options,
        start: "scan",
        states: { scan: { cases: [], default: { decision: "ignore" }, end: { decision: "allow", reason: ["ok"] } } },
      };
      const program = compilePolicyDocument(validatePolicyDocument(document));
      const candidate = createDslPolicy(program, "/policy/matrix.policy.json");
      const result = candidate.evaluateWithTrace({ kind: "invocation", executable: null, executableIdentity: { qualification: "unknown", reason: "unresolved-spelling" }, argv: [{ kind: "known", value: `-${"v".repeat(clusterBytes)}` }], environment: {}, missingBindings: "unset", redirects: [], assignments: {}, span: { start: 0, end: 0 }, provenance: { route: ["direct"] }, inPipeline: false, processEffect: "none" });

      // At most one trace entry per consumed byte plus the terminal decision.
      expect(result.steps.length, `P=${optionCount}, B=${clusterBytes}`).toBeLessThanOrEqual(clusterBytes + 1);
      expect(result.steps.filter((step) => step.action === "option")).toHaveLength(clusterBytes);
      expect(new Set(result.steps.map((step) => step.source)).size).toBeLessThanOrEqual(2);
      expect(JSON.stringify(result).length).toBeLessThan((clusterBytes + 1) * 220);
      expect(program.metrics.cases).toBeLessThanOrEqual(optionCount);
    }
  }
});
