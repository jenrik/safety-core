import { describe, expect, test } from "bun:test";

import {
  analysisFailure,
  appendOutcomeSummary,
  deny,
  emptyOutcomeSummary,
  failure,
  finalize,
  indeterminate,
  materializeOutcomeSummary,
  mergeOutcomeSummaries,
  policyDeny,
  policySafe,
  safe,
  strongestOutcome,
} from "../src/bash/outcome.ts";
import {
  DEFAULT_BASH_ANALYSIS_LIMITS,
  runSteps,
  type BashAnalysisLimits,
  type DispatchTarget,
  type Step,
} from "../src/bash/runner.ts";
import { fromInitialEnvironment, lookupBinding } from "../src/bash/environment.ts";
import type { SourceSpan } from "../src/bash/cst.ts";
import type { Outcome } from "../src/bash/outcome.ts";
import { BashParserFailure } from "../src/shell.ts";

const span: SourceSpan = { start: 3, end: 9 };

describe("Bash authorization outcomes", () => {
  test("finalizes only complete safe evidence as allow", () => {
    expect(finalize([safe(), safe()])).toEqual({ kind: "allow" });
  });

  test("finalizes indeterminate and failure evidence as neutral", () => {
    expect(finalize([safe(), indeterminate(span)])).toEqual({ kind: "neutral" });
    expect(finalize([safe(), failure(span)])).toEqual({ kind: "neutral" });
  });

  test("finalizes deny evidence as deny", () => {
    expect(finalize([safe(), deny(span)])).toEqual({ kind: "deny", span });
  });

  test("retains policy evidence observed after the first denial", () => {
    const outcome = strongestOutcome([
      policyDeny(span, { name: "gh-api", decision: "deny" }),
      policyDeny(span, { name: "gh-pr-create", decision: "deny" }),
    ]);

    expect(outcome.kind).toBe("deny");
    expect(outcome.policies?.map((policy) => policy.name)).toEqual(["gh-api", "gh-pr-create"]);
  });

  test("uses redacted immutable evidence with source provenance", () => {
    const outcome = analysisFailure("max-steps", span);

    expect(outcome).toEqual({
      kind: "failure",
      reason: "analysis-failure",
      budget: "max-steps",
      span,
    });
    expect(Object.isFrozen(outcome)).toBeTrue();
    expect(Object.isFrozen(outcome.span)).toBeTrue();
    expect(outcome).not.toHaveProperty("value");
    expect(() => { (outcome.span as { start: number }).start = 0; }).toThrow();
  });

  test("does not retain ordinary safe outcomes", () => {
    const empty = emptyOutcomeSummary();
    let summary = empty;

    for (let index = 0; index < 10_000; index++) summary = appendOutcomeSummary(summary, safe());

    expect(summary).toBe(empty);
    expect(materializeOutcomeSummary(summary)).toBe(safe());
  });

  test("retains a shared policy prefix once when branches rejoin", () => {
    const prefix = appendOutcomeSummary(emptyOutcomeSummary(), labeledSafe("prefix"));
    const left = appendOutcomeSummary(prefix, labeledSafe("left"));
    const right = appendOutcomeSummary(prefix, labeledSafe("right"));

    const summary = mergeOutcomeSummaries([left, right]);
    expect(left.events.kind).toBe("append");
    expect(right.events.kind).toBe("append");
    if (left.events.kind === "append") expect(left.events.previous).toBe(prefix.events);
    if (right.events.kind === "append") expect(right.events.previous).toBe(prefix.events);
    const merged = materializeOutcomeSummary(summary);

    expect(merged.policies?.map((policy) => policy.reason)).toEqual(["prefix", "left", "right"]);
    expect(merged.policy?.reason).toBe("right");

    const descendantThenPrefix = materializeOutcomeSummary(mergeOutcomeSummaries([left, prefix]));
    expect(descendantThenPrefix.policies?.map((policy) => policy.reason)).toEqual(["prefix", "left"]);
    expect(descendantThenPrefix.policy?.reason).toBe("left");
  });

  test("retains physically distinct equal policy observations", () => {
    const first = appendOutcomeSummary(emptyOutcomeSummary(), labeledSafe("same"));
    const second = appendOutcomeSummary(emptyOutcomeSummary(), labeledSafe("same"));

    expect(materializeOutcomeSummary(mergeOutcomeSummaries([first, second])).policies).toHaveLength(2);
  });

  test("property: compact sequential summaries equal the flat outcome reduction", () => {
    const random = lcg(0x0ca7c0de);
    for (let iteration = 0; iteration < 128; iteration++) {
      const outcomes: Outcome[] = [];
      const length = 1 + (random() % 64);
      for (let index = 0; index < length; index++) {
        const candidate = random() % 6;
        outcomes.push(candidate === 0
          ? safe()
          : candidate === 1
            ? labeledSafe(`${iteration}-${index}`)
            : candidate === 2
              ? indeterminate({ start: index, end: index + 1 })
              : candidate === 3
                ? failure({ start: index, end: index + 1 })
                : candidate === 4
                  ? analysisFailure("max-steps", { start: index, end: index + 1 })
                  : deny({ start: index, end: index + 1 }));
      }

      const summary = outcomes.reduce(appendOutcomeSummary, emptyOutcomeSummary());
      expect(materializeOutcomeSummary(summary)).toEqual(strongestOutcome(outcomes));
    }
  });

  test("property: shared policy storage materializes proportional evidence", () => {
    let prefix = emptyOutcomeSummary();
    const prefixLength = 1_000;
    for (let index = 0; index < prefixLength; index++) {
      prefix = appendOutcomeSummary(prefix, labeledSafe(`prefix-${index}`));
    }
    const branchCount = 64;
    const branches = Array.from({ length: branchCount }, (_, index) =>
      appendOutcomeSummary(prefix, labeledSafe(`branch-${index}`)));
    for (const branch of branches) {
      expect(branch.events.kind).toBe("append");
      if (branch.events.kind === "append") expect(branch.events.previous).toBe(prefix.events);
    }

    const policies = materializeOutcomeSummary(mergeOutcomeSummaries(branches)).policies ?? [];

    expect(policies).toHaveLength(prefixLength + branchCount);
    expect(policies[0]?.reason).toBe("prefix-0");
    expect(policies.at(-1)?.reason).toBe(`branch-${branchCount - 1}`);
  });

  test("property: nested shared-prefix merges preserve first-occurrence order", () => {
    const random = lcg(0x5a4ed109);
    for (let iteration = 0; iteration < 64; iteration++) {
      const prefixLength = 1 + (random() % 16);
      let prefix = emptyOutcomeSummary();
      const expected: string[] = [];
      for (let index = 0; index < prefixLength; index++) {
        const reason = `prefix-${iteration}-${index}`;
        expected.push(reason);
        prefix = appendOutcomeSummary(prefix, labeledSafe(reason));
      }
      const branchCount = 2 + (random() % 8);
      const branches = Array.from({ length: branchCount }, (_, index) => {
        const reason = `branch-${iteration}-${index}`;
        expected.push(reason);
        return appendOutcomeSummary(prefix, labeledSafe(reason));
      });
      const nested = branches.reduce(
        (summary, branch) => mergeOutcomeSummaries([summary, branch]),
        emptyOutcomeSummary(),
      );

      expect(materializeOutcomeSummary(nested).policies?.map((policy) => policy.reason)).toEqual(expected);
    }
  });
});

describe("iterative Bash authorization runner", () => {
  test("stops immediately after deny without running later targets", () => {
    let laterTargetRan = false;
    const initial: Step = fork([
      target(() => result(deny(span))),
      target(() => {
        laterTargetRan = true;
        return result(safe());
      }),
    ]);

    const completed = runSteps(initial, limits());

    expect(completed.outcome).toEqual(deny(span));
    expect(completed.verdict).toEqual({ kind: "deny", span });
    expect(laterTargetRan).toBeFalse();
  });

  test("keeps indeterminate and failure evidence sticky while evaluating later targets", () => {
    let safeTargetRan = false;
    const initial: Step = fork([
      target(() => result(indeterminate(span))),
      target(() => result(failure(span))),
      target(() => {
        safeTargetRan = true;
        return result(safe());
      }),
    ]);

    const completed = runSteps(initial, limits());

    expect(completed.outcome).toEqual(failure(span));
    expect(completed.verdict).toEqual({ kind: "neutral" });
    expect(safeTargetRan).toBeTrue();
  });

  test("records a thrown target as redacted failure and continues later work", () => {
    let safeTargetRan = false;
    const initial: Step = fork([
      target(() => { throw new Error(); }),
      target(() => {
        safeTargetRan = true;
        return result(safe());
      }),
    ]);

    const completed = runSteps(initial, limits());

    expect(completed.outcome).toEqual(failure(span));
    expect(completed.verdict).toEqual({ kind: "neutral" });
    expect(safeTargetRan).toBeTrue();
  });

  test("rethrows a parser deployment assertion instead of deferring it", () => {
    const initial: Step = continueWith(target(() => {
      throw new BashParserFailure("parser disappeared");
    }));

    expect(() => runSteps(initial, limits())).toThrow(BashParserFailure);
  });

  test("redacts unrecognized fields from foreign outcome objects", () => {
    const foreignOutcome = {
      kind: "indeterminate",
      span,
      unexpected: "opaque",
    } as unknown as Outcome;
    const initial: Step = {
      kind: "result",
      state: fromInitialEnvironment(),
      outcome: foreignOutcome,
      span,
    };

    const completed = runSteps(initial, limits());

    expect(completed.evidence[0]).toEqual(indeterminate(span));
    expect(completed.evidence[0]).not.toHaveProperty("unexpected");
  });

  test("returns redacted failure when a self-requeueing continuation exhausts max steps", () => {
    let repeating: Step;
    const requeue = target(() => repeating);
    repeating = continueWith(requeue);

    const completed = runSteps(repeating, limits({ maxSteps: 3 }));

    expect(completed.outcome).toEqual(analysisFailure("max-steps", span));
    expect(completed.verdict).toEqual({ kind: "neutral" });
  });

  for (const [field, budget] of [
    ["maxFunctionDepth", "max-function-depth"],
    ["maxNestedScriptDepth", "max-nested-script-depth"],
    ["maxSteps", "max-steps"],
    ["maxWorkItems", "max-work-items"],
  ] as const) {
    for (const invalid of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0.5, -1]) {
      test(`rejects ${String(invalid)} for ${field} before scheduling work`, () => {
        const completed = runSteps(result(safe()), limits({ [field]: invalid }));

        expect(completed.outcome).toEqual(analysisFailure(budget, span));
        expect(completed.verdict).toEqual({ kind: "neutral" });
      });
    }
  }

  test("runs admitted fork targets exactly once in source order without changing caller snapshots", () => {
    const calls: string[] = [];
    const state = fromInitialEnvironment({ STABLE: "before" });
    const targets = Object.freeze([
      target((received) => {
        calls.push("first");
        expect(received).toBe(state);
        return result(safe());
      }),
      target((received) => {
        calls.push("second");
        expect(received).toBe(state);
        return result(safe());
      }),
      target((received) => {
        calls.push("third");
        expect(received).toBe(state);
        return result(safe());
      }),
    ]);
    const initial: Step = Object.freeze({ kind: "fork", state, targets, span });
    const initialSnapshot = {
      kind: initial.kind,
      state: initial.state,
      targets: [...initial.targets],
      span: { ...initial.span },
    };
    const stateSnapshot = { budgets: { ...state.budgets }, stable: lookupBinding(state, "STABLE").value };

    expect(runSteps(initial, limits()).verdict).toEqual({ kind: "allow" });
    expect(calls).toEqual(["first", "second", "third"]);
    expect(initial).toEqual(initialSnapshot);
    expect(initial.targets).toBe(targets);
    expect(initial.targets).toEqual(initialSnapshot.targets);
    expect(initial.state).toBe(state);
    expect(state.budgets).toEqual(stateSnapshot.budgets);
    expect(lookupBinding(state, "STABLE").value).toEqual(stateSnapshot.stable);
  });

  test("continues unrelated work after a function-depth failure", () => {
    let safeTargetRan = false;
    const initial: Step = fork([
      target(() => result(safe()), { functionDepth: 2 }),
      target(() => {
        safeTargetRan = true;
        return result(safe());
      }),
    ]);

    const completed = runSteps(initial, limits({ maxFunctionDepth: 1 }));

    expect(completed.outcome).toEqual(analysisFailure("max-function-depth", span));
    expect(completed.verdict).toEqual({ kind: "neutral" });
    expect(safeTargetRan).toBeTrue();
  });

  test("continues unrelated work after a nested-script-depth failure", () => {
    let safeTargetRan = false;
    const initial: Step = fork([
      target(() => result(safe()), { nestedScriptDepth: 2 }),
      target(() => {
        safeTargetRan = true;
        return result(safe());
      }),
    ]);

    const completed = runSteps(initial, limits({ maxNestedScriptDepth: 1 }));

    expect(completed.outcome).toEqual(analysisFailure("max-nested-script-depth", span));
    expect(completed.verdict).toEqual({ kind: "neutral" });
    expect(safeTargetRan).toBeTrue();
  });

  test("property: bounded nested forks fail before queueing unbounded work", () => {
    const random = lcg(0x1f123bb5);

    for (let iteration = 0; iteration < 32; iteration++) {
      const maxWorkItems = 1 + (random() % 64);
      const fanout = 2 + (random() % 3);
      let growth: DispatchTarget;
      growth = target(() => fork(Array.from({ length: fanout }, () => growth)));

      const completed = runSteps(continueWith(growth), limits({
        maxSteps: maxWorkItems * 4,
        maxWorkItems,
      }));

      expect(completed.outcome).toEqual(analysisFailure("max-work-items", span));
      expect(completed.verdict).toEqual({ kind: "neutral" });
    }
  });

  test("drains outer-runner work admitted before a later queue admission failure", () => {
    let denyCalls = 0;
    const growth = target(() => fork([target(() => result(safe())), target(() => result(safe())), target(() => result(safe()))]));
    const denied = target(() => {
      denyCalls++;
      return result(deny(span));
    });

    const completed = runSteps(fork([growth, denied]), limits({ maxSteps: 20, maxWorkItems: 2 }));

    expect(completed.outcome).toEqual(deny(span));
    expect(denyCalls).toBe(1);
  });

  test("does not fabricate an outer-runner denial for work rejected before admission", () => {
    let denyCalls = 0;
    const denied = target(() => {
      denyCalls++;
      return result(deny(span));
    });
    const completed = runSteps(fork([target(() => result(safe())), denied, target(() => result(safe()))]), limits({
      maxSteps: 20,
      maxWorkItems: 2,
    }));

    expect(completed.outcome).toEqual(analysisFailure("max-work-items", span));
    expect(denyCalls).toBe(0);
  });

  test("property: generated continuation chains of at least 2,500 steps never consume the JavaScript stack", () => {
    const random = lcg(0x4d595df4);

    for (let iteration = 0; iteration < 16; iteration++) {
      const length = 2_500 + (random() % 501);
      let step: Step = result(safe());
      for (let index = 0; index < length; index++) {
        const successor = step;
        step = continueWith(target(() => successor));
      }

      const completed = runSteps(step, limits({ maxSteps: length + 1, maxWorkItems: 1 }));
      expect(completed.verdict).toEqual({ kind: "allow" });
    }
  });
});

function limits(overrides: Partial<BashAnalysisLimits> = {}): BashAnalysisLimits {
  return { ...DEFAULT_BASH_ANALYSIS_LIMITS, ...overrides };
}

function target(
  run: DispatchTarget["run"],
  depth: Partial<Pick<DispatchTarget, "functionDepth" | "nestedScriptDepth">> = {},
): DispatchTarget {
  return {
    span,
    functionDepth: depth.functionDepth ?? 0,
    nestedScriptDepth: depth.nestedScriptDepth ?? 0,
    run,
  };
}

function continueWith(targetValue: DispatchTarget): Step {
  return { kind: "continue", state: fromInitialEnvironment(), target: targetValue, span };
}

function fork(targets: readonly DispatchTarget[]): Step {
  return { kind: "fork", state: fromInitialEnvironment(), targets, span };
}

function result(outcome: ReturnType<typeof safe> | ReturnType<typeof indeterminate> | ReturnType<typeof failure> | ReturnType<typeof deny>): Step {
  return { kind: "result", state: fromInitialEnvironment(), outcome, span };
}

function labeledSafe(reason: string) {
  return policySafe({ name: "strict-read-only", decision: "allow", reason, readOnly: { tool: "test" } });
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
