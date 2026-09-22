import { describe, expect, test } from "bun:test";

import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { validatePolicyDocument } from "../src/policy/dsl/validate.ts";
import { evaluatePolicyEvents } from "../src/policy/evaluate.ts";
import { renderExplainTrace } from "../src/policy/trace.ts";
import type { InvocationView, ValidatedBashPolicy } from "../src/policy/types.ts";

const source = "/policy/example.policy.json";

function event(argv: readonly ({ readonly kind: "known"; readonly value: string } | { readonly kind: "unknown"; readonly reason: { readonly kind: string } })[]): InvocationView {
  return {
    kind: "invocation",
    executable: { kind: "known", value: "tool" },
    executableIdentity: { qualification: "incomplete", spelling: "tool", basename: "tool", chain: [], failure: { kind: "not-found" } },
    argv,
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  };
}

function policy(document: Record<string, unknown>) {
  return createDslPolicy(compilePolicyDocument(validatePolicyDocument(document)), source);
}

const base = (): Record<string, any> => ({
  language: "safety-core/bash-policy-v1",
  layer: "permission",
  select: [{ kind: "invocation" }],
  registers: { seen: { type: "bool", initial: false }, value: { type: "inputRef", initial: null }, count: { type: "count", max: 8, initial: 0 } },
  options: {
    output: { names: ["-o", "--output"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { value: { ref: "option.value" }, count: 1 } },
    verbose: { names: ["-v"], value: "absent", forms: [], availableIn: "*", set: { seen: true, count: 2 } },
  },
  start: "command",
  states: {
    command: {
      cases: [
        { when: { call: "equals", args: [{ ref: "word" }, "run"] }, action: { consume: "word", next: "tail", set: { seen: true, count: 3 } } },
        { when: true, action: { decision: "deny", reason: ["unknown ", { ref: "word" }] } },
      ],
      default: { decision: "ignore" },
      end: { decision: "ignore" },
    },
    tail: {
      cases: [{ when: { ref: "seen" }, action: { consume: "word", next: "tail", set: { count: { ref: "count" } } } }],
      default: { decision: "deny", reason: ["unexpected ", { ref: "word" }] },
      end: { decision: "allow", reason: ["output=", { ref: "value" }], audit: { count: { ref: "count" } } },
    },
  },
});

describe("DCRM evaluation", () => {
  test("honors first-match order, guards against pre-state, and applies updates simultaneously", () => {
    const document = base();
    document.states.command.cases.unshift({ when: true, action: { consume: "word", next: "tail", set: { seen: true, count: 1 } } });
    const decision = policy(document).evaluate(event([{ kind: "known", value: "run" }]));
    expect(decision).toMatchObject({ kind: "allow", reason: [{ kind: "literal", value: "output=" }, { kind: "value", value: null }], audit: { count: 1 } });
  });

  test("consumes required values in separate, attached, equals, and cluster forms", () => {
    for (const [argv, expected] of [[["run", "-o", "one"], "one"], [["run", "-otwo"], "two"], [["run", "--output=three"], "three"], [["run", "-vofour"], "four"]] as const) {
      const decision = policy(base()).evaluate(event(argv.map((value) => ({ kind: "known" as const, value }))));
      expect(decision, argv.join(" ")).toMatchObject({ kind: "allow", reason: [{ kind: "literal", value: "output=" }, { kind: "value", value: expected }] });
    }
  });

  test("distinguishes missing required values, optional absent values, unknown input, duplicates, conflicts, and --", () => {
    const required = policy(base());
    expect(required.evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: "-o" }]))).toMatchObject({ kind: "deny" });
    expect(required.evaluate(event([{ kind: "unknown", reason: { kind: "expansion" } }]))).toMatchObject({ kind: "deny" });
    expect(required.evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: "--" }, { kind: "known", value: "-o=value" }]))).toMatchObject({ kind: "allow" });
    expect(required.evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: "-o" }, { kind: "known", value: "first" }, { kind: "known", value: "--output=second" }]))).toMatchObject({
      kind: "allow", reason: [{ kind: "literal", value: "output=" }, { kind: "value", value: "second" }],
    });

    const optional = base();
    optional.options.output.value = "optional";
    expect(policy(optional).evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: "-o" }, { kind: "known", value: "-v" }]))).toMatchObject({
      kind: "allow", reason: [{ kind: "literal", value: "output=" }, { kind: "value", value: null }],
    });

    const conflict = base();
    conflict.states.tail.cases = [{ when: { ref: "seen" }, action: { decision: "deny", reason: ["conflicting operand"] } }];
    expect(policy(conflict).evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: "-v" }, { kind: "known", value: "operand" }]))).toMatchObject({ kind: "deny" });
  });

  test("reserves declared spellings with disabled forms while -- restores ordinary operands", () => {
    const restricted = base();
    restricted.options.output.forms = ["separate"];
    for (const spelling of ["--output=value", "-ovalue"]) {
      expect(policy(restricted).evaluate(event([{ kind: "known", value: "run" }, { kind: "known", value: spelling }])), spelling).toMatchObject({ kind: "deny" });
    }
    expect(policy(restricted).evaluate(event([
      { kind: "known", value: "run" }, { kind: "known", value: "--" },
      { kind: "known", value: "-o" }, { kind: "known", value: "--output" },
    ]))).toMatchObject({ kind: "allow" });
  });

  test("unknown builtin operands select a deterministic terminal instead of coercing a Symbol", () => {
    const document = base();
    document.states.command.cases = [{
      when: { call: "boundedIntAtMost", args: [{ call: "parseBoundedInt", args: [{ ref: "word" }, 3] }, 3] },
      action: { decision: "allow", reason: ["known bounded count"] },
    }];
    document.states.command.default = { decision: "deny", reason: ["unknown count"] };
    expect(policy(document).evaluate(event([{ kind: "unknown", reason: { kind: "expansion" } }]))).toMatchObject({ kind: "deny" });
  });

  test("defensively treats an invalid manually supplied regex program as an unmatched guard", () => {
    const document = base();
    document.options = {};
    document.states.command.cases = [{
      when: { call: "linearRegex", args: [{ ref: "word" }, "safe"] },
      action: { decision: "allow", reason: ["matched"] },
    }];
    document.states.command.default = { decision: "deny", reason: ["unmatched"] };
    const compiled = compilePolicyDocument(validatePolicyDocument(document));
    const forced = {
      ...compiled,
      states: {
        ...compiled.states,
        command: {
          ...compiled.states.command,
          cases: [{ ...compiled.states.command.cases[0]!, when: { call: "linearRegex", args: [{ ref: "word" }, "[z-a]"] } }],
        },
      },
    };
    expect(createDslPolicy(forced, source).evaluate(event([{ kind: "known", value: "value" }]))).toMatchObject({ kind: "deny" });
  });

  test("caches folds and records machine-step provenance", () => {
    const document = base();
    document.folds = { hasRun: { collection: "argv", operation: "any", when: { call: "equals", args: [{ ref: "fold.item" }, "run"] } } };
    document.states.command.cases[0].action.fold = ["hasRun"];
    const candidate = policy(document);
    const result = candidate.evaluateWithTrace(event([{ kind: "known", value: "run" }]));
    expect(result.steps[0]).toMatchObject({ state: "command", source: "$.states.command.cases[0]" });
    expect(result.steps.some((step: { readonly folds: readonly string[] }) => step.folds.includes("hasRun"))).toBeTrue();
  });

  test("attaches DSL steps to JSON and human explain traces", () => {
    const candidate = policy(base());
    const input = event([{ kind: "known", value: "run" }]);
    const evaluation = evaluatePolicyEvents([input], [candidate as unknown as ValidatedBashPolicy], { complete: true });
    const trace = { version: 1 as const, decision: evaluation.decision, analysis: { complete: true }, sources: [{ canonicalPath: source, sha256: "a".repeat(64) }], events: [input], decisions: evaluation.traces };
    expect(evaluation.traces[0]?.dslSteps).toHaveLength(2);
    expect(renderExplainTrace(trace, false)).toContain("transition $.states.command.cases[0] state=command argv=0");
    expect(JSON.parse(renderExplainTrace(trace, true)).decisions[0].dslSteps[0]).toMatchObject({ source: "$.states.command.cases[0]" });
  });

  test("retains original nested fragment pointers at every shared expansion site", () => {
    const document = base();
    document.fragments = {
      leaf: { cases: [{ when: true, action: { consume: "word", next: "tail" } }] },
      firstParent: { uses: ["leaf"], cases: [] },
      secondParent: { uses: ["leaf"], cases: [] },
    };
    document.states.command.fragments = ["firstParent", "secondParent"];
    document.states.command.cases = [];
    const program = compilePolicyDocument(validatePolicyDocument(document));
    expect(program.states.command.cases.filter((entry) => entry.origin === "fragment:leaf").map((entry) => entry.source))
      .toEqual(["$.fragments.leaf.cases[0]", "$.fragments.leaf.cases[0]"]);
    const result = createDslPolicy(program, source).evaluateWithTrace(event([{ kind: "known", value: "run" }]));
    expect(result.steps[0]?.source).toBe("$.fragments.leaf.cases[0]");
  });
});
