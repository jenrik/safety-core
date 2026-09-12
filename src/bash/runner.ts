import type { SourceSpan } from "./cst.js";
import type { Environment } from "./environment.js";
import {
  analysisFailure,
  failure,
  finalize,
  redactOutcome,
  strongestOutcome,
  type AnalysisBudget,
  type AuthorizationVerdict,
  type Outcome,
} from "./outcome.js";

export interface BashAnalysisLimits {
  readonly maxFunctionDepth: number;
  readonly maxNestedScriptDepth: number;
  readonly maxSteps: number;
  readonly maxWorkItems: number;
}

export const DEFAULT_BASH_ANALYSIS_LIMITS: BashAnalysisLimits = Object.freeze({
  maxFunctionDepth: 128,
  maxNestedScriptDepth: 64,
  maxSteps: 100_000,
  maxWorkItems: 10_000,
});

/** A pure, statically-described dispatch operation supplied by the walker or a handler. */
export interface DispatchTarget {
  readonly span: SourceSpan;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  readonly run: (state: Environment) => Step;
}

export type Step =
  | { readonly kind: "continue"; readonly state: Environment; readonly target: DispatchTarget; readonly span: SourceSpan }
  | { readonly kind: "fork"; readonly state: Environment; readonly targets: readonly DispatchTarget[]; readonly span: SourceSpan }
  | { readonly kind: "result"; readonly state: Environment; readonly outcome: Outcome; readonly span: SourceSpan };

export interface RunStepsResult {
  /** The strongest observed evidence, retained for the next walker layer. */
  readonly outcome: Outcome;
  /** Native harness conversion: only total safety becomes allow. */
  readonly verdict: AuthorizationVerdict;
  /** Redacted evidence observed before completion or immediate denial. */
  readonly evidence: readonly Outcome[];
}

/**
 * Executes continuation work with an explicit LIFO agenda. No successor is
 * invoked recursively, so both linear chains and branching work stay bounded
 * by the configured structural limits rather than the JavaScript call stack.
 */
export function runSteps(initial: Step, limits: BashAnalysisLimits = DEFAULT_BASH_ANALYSIS_LIMITS): RunStepsResult {
  const invalidBudget = invalidLimitBudget(limits);
  if (invalidBudget) return complete([analysisFailure(invalidBudget, initial.span)]);

  const agenda: Step[] = [initial];
  const evidence: Outcome[] = [];
  let steps = 0;

  while (agenda.length > 0) {
    const step = agenda.pop()!;
    if (steps >= limits.maxSteps) {
      evidence.push(analysisFailure("max-steps", step.span));
      return complete(evidence);
    }
    steps++;

    switch (step.kind) {
      case "result":
        if (record(evidence, step.outcome)) return complete(evidence);
        break;
      case "continue": {
        const budget = exhaustedDepthBudget(step.target, limits);
        if (budget) {
          evidence.push(analysisFailure(budget, step.target.span));
          break;
        }
        if (agenda.length >= limits.maxWorkItems) {
          evidence.push(analysisFailure("max-work-items", step.span));
          break;
        }
        const successor = runTarget(step.target, step.state, evidence);
        if (successor) agenda.push(successor);
        if (hasDeny(evidence)) return complete(evidence);
        break;
      }
      case "fork": {
        if (agenda.length + step.targets.length > limits.maxWorkItems) {
          evidence.push(analysisFailure("max-work-items", step.span));
          break;
        }
        for (let index = step.targets.length - 1; index >= 0; index--) {
          const target = step.targets[index]!;
          agenda.push({ kind: "continue", state: step.state, target, span: target.span });
        }
        break;
      }
    }
  }

  return complete(evidence);
}

function runTarget(target: DispatchTarget, state: Environment, evidence: Outcome[]): Step | undefined {
  try {
    return target.run(state);
  } catch {
    evidence.push(failure(target.span));
    return undefined;
  }
}

function exhaustedDepthBudget(target: DispatchTarget, limits: BashAnalysisLimits): AnalysisBudget | undefined {
  if (target.functionDepth > limits.maxFunctionDepth) return "max-function-depth";
  if (target.nestedScriptDepth > limits.maxNestedScriptDepth) return "max-nested-script-depth";
  return undefined;
}

function invalidLimitBudget(limits: BashAnalysisLimits): AnalysisBudget | undefined {
  if (!isValidLimit(limits.maxFunctionDepth)) return "max-function-depth";
  if (!isValidLimit(limits.maxNestedScriptDepth)) return "max-nested-script-depth";
  if (!isValidLimit(limits.maxSteps)) return "max-steps";
  if (!isValidLimit(limits.maxWorkItems)) return "max-work-items";
  return undefined;
}

function isValidLimit(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function record(evidence: Outcome[], outcome: Outcome): boolean {
  const redacted = redactOutcome(outcome);
  evidence.push(redacted);
  return redacted.kind === "deny";
}

function hasDeny(evidence: readonly Outcome[]): boolean {
  return evidence.some((outcome) => outcome.kind === "deny");
}

function complete(evidence: readonly Outcome[]): RunStepsResult {
  const observed = Object.freeze([...evidence]);
  const outcome = strongestOutcome(observed);
  return Object.freeze({ outcome, verdict: finalize(observed), evidence: observed });
}
