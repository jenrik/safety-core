import { createCommandRegistry, dispatchCommand, preflightCommand } from "./bash/dispatch.js";
import { fromFilteredInitialEnvironment, fromInitialEnvironment, fromVerifiedInitialEnvironment } from "./bash/environment.js";
import { failure } from "./bash/outcome.js";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type BashAnalysisLimits } from "./bash/runner.js";
import { walkProgram } from "./bash/walker.js";
import { parseBashProgram } from "./shell.js";
import { evaluatePolicyEvents } from "./policy/evaluate.js";
import { projectExecutionGapEvent } from "./policy/events.js";
import type { BashPolicyAnalysis, BashPolicyEvent, PolicyEvaluation, ValidatedBashPolicy } from "./policy/types.js";

export type BashInitialEnvironment =
  | { readonly kind: "unavailable" }
  | { readonly kind: "verified"; readonly values: Readonly<Record<string, string>> }
  | { readonly kind: "filtered"; readonly values: Readonly<Record<string, string>>; readonly unset: readonly string[] };

export interface BashPolicyAnalysisOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  readonly initialEnvironment?: BashInitialEnvironment;
  readonly policies: readonly ValidatedBashPolicy[];
}

export interface BashPolicyEvaluation extends PolicyEvaluation {
  readonly events: readonly BashPolicyEvent[];
  readonly analysis: BashPolicyAnalysis;
}

/** Analyze Bash exclusively through the supplied loaded generic policy set. */
export function analyzeBashWithPolicies(options: BashPolicyAnalysisOptions): BashPolicyEvaluation {
  const limits = options.limits ?? DEFAULT_BASH_ANALYSIS_LIMITS;
  const environment = initialEnvironment(options.initialEnvironment, limits);
  const parsed = parseBashProgram(options.source);
  const program = parsed.kind === "parse-failure" ? parsed.program : parsed;
  const events: BashPolicyEvent[] = [];
  if (parsed.kind === "parse-failure") {
    events.push(projectExecutionGapEvent("source-parse-failure", {
      environment,
      span: parsed.span,
      provenance: { route: ["direct"] },
      inPipeline: false,
      processEffect: "none",
    }));
  }
  const registry = createCommandRegistry();
  const initial = walkProgram(program, {
    environment,
    dispatchCommand: (request) => dispatchCommand(request, registry),
    preflightCommand: (request) => preflightCommand(request, registry),
    recordPolicyEvent: (event) => events.push(event),
  }, parsed.kind === "parse-failure" ? failure(parsed.span) : undefined);
  const completed = runSteps(initial, limits);
  const analysis = Object.freeze({ complete: completed.outcome.kind !== "failure" });
  const evaluated = evaluatePolicyEvents(Object.freeze([...events]), options.policies, analysis);
  return Object.freeze({
    // Structural walker denials always win, independent of policy coverage.
    decision: completed.outcome.kind === "deny" ? "deny" : evaluated.decision,
    traces: evaluated.traces,
    events: Object.freeze([...events]),
    analysis,
  });
}

function initialEnvironment(initial: BashInitialEnvironment | undefined, limits: BashAnalysisLimits) {
  const budgets = Object.freeze({
    functionDepth: limits.maxFunctionDepth,
    nestedScriptDepth: limits.maxNestedScriptDepth,
    steps: limits.maxSteps,
    workItems: limits.maxWorkItems,
  });
  if (initial?.kind === "verified") return fromVerifiedInitialEnvironment(initial.values, budgets);
  if (initial?.kind === "filtered") return fromFilteredInitialEnvironment(initial.values, initial.unset, budgets);
  return fromInitialEnvironment({}, budgets);
}
