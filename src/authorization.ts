import { createCommandRegistry, dispatchCommand, type CommandHandler } from "./bash/dispatch.js";
import { fromInitialEnvironment } from "./bash/environment.js";
import { indeterminate, type AuthorizationVerdict, type PolicyEvidence } from "./bash/outcome.js";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type BashAnalysisLimits, type RunStepsResult } from "./bash/runner.js";
import { walkProgram } from "./bash/walker.js";
import { httpHandlers } from "./bash/handlers/http.js";
import { kubectlHandler } from "./bash/handlers/kubectl.js";
import { readerHandlers } from "./bash/handlers/readers.js";
import { parseBashProgram } from "./shell.js";

export interface BashAuthorizationOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  /** Explicit policy handlers define the active profiles for this analysis. */
  readonly handlers?: readonly CommandHandler[];
  /** Compatibility profiles can opt out of unrelated baseline policy handlers. */
  readonly includeBaseHandlers?: boolean;
}

export interface BashAuthorizationAnalysis {
  readonly verdict: AuthorizationVerdict;
  readonly outcome: RunStepsResult["outcome"];
  readonly evidence: readonly RunStepsResult["evidence"][number][];
  /** Vetted policy evidence only; it never exposes normalized argv or environments. */
  readonly policy: PolicyEvidence | null;
  readonly policies: readonly PolicyEvidence[];
}

const baseHandlers = Object.freeze([...readerHandlers, ...httpHandlers, kubectlHandler]);

/**
 * Analyze a Bash source string with only an explicit empty initial environment.
 * The core never reads process.env; unresolved ambient references stay neutral.
 */
export function analyzeBashAuthorization(options: BashAuthorizationOptions): BashAuthorizationAnalysis {
  const program = parseBashProgram(options.source);
  if (program.kind === "parse-failure") {
    const outcome = indeterminate(program.span);
    return freeze({
      verdict: Object.freeze({ kind: "neutral" }),
      outcome,
      evidence: Object.freeze([outcome]),
      policy: null,
      policies: Object.freeze([]),
    });
  }
  const registry = createCommandRegistry([...(options.includeBaseHandlers === false ? [] : baseHandlers), ...(options.handlers ?? [])]);
  const initial = walkProgram(program, {
    environment: fromInitialEnvironment({}, toEnvironmentBudgets(options.limits)),
    dispatchCommand: (request) => dispatchCommand(request, registry),
  });
  const completed = runSteps(initial, options.limits ?? DEFAULT_BASH_ANALYSIS_LIMITS);
  return freeze({
    verdict: completed.verdict,
    outcome: completed.outcome,
    evidence: Object.freeze([...completed.evidence]),
    policy: policyFrom(completed),
    policies: policiesFrom(completed),
  });
}

function policyFrom(completed: RunStepsResult): PolicyEvidence | null {
  return policiesFrom(completed)[0] ?? null;
}

function policiesFrom(completed: RunStepsResult): readonly PolicyEvidence[] {
  return Object.freeze([...(completed.outcome.policies ?? [])]);
}

function toEnvironmentBudgets(limits: BashAnalysisLimits | undefined) {
  const active = limits ?? DEFAULT_BASH_ANALYSIS_LIMITS;
  return Object.freeze({
    functionDepth: active.maxFunctionDepth,
    nestedScriptDepth: active.maxNestedScriptDepth,
    steps: active.maxSteps,
    workItems: active.maxWorkItems,
  });
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
