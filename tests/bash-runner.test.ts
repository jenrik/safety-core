import { describe, expect, test } from "bun:test";

import {
  analysisFailure,
  deny,
  failure,
  finalize,
  indeterminate,
  safe,
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

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
