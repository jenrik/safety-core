import { createCommandRegistry, dispatchCommand, preflightCommand, type PolicyObserver } from "./bash/dispatch.js";
import { fromFilteredInitialEnvironment, fromInitialEnvironment, fromVerifiedInitialEnvironment } from "./bash/environment.js";
import { failure, type AuthorizationVerdict, type PolicyEvidence } from "./bash/outcome.js";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type BashAnalysisLimits } from "./bash/runner.js";
import { walkProgram } from "./bash/walker.js";
import { parseBashProgram } from "./shell.js";
import { evaluatePolicyEvents } from "./policy/evaluate.js";
import { projectExecutionGapEvent } from "./policy/events.js";
import type { BashPolicyAnalysis, BashPolicyEvent, PolicyEvaluation, ValidatedBashPolicy } from "./policy/types.js";
import { unavailableExecutableFilesystem, type ExecutableFilesystem } from "./policy/filesystem.js";
import { readerHandlers } from "./bash/handlers/readers.js";
import { httpHandlers } from "./bash/handlers/http.js";
import { kubectlHandler } from "./bash/handlers/command-kubectl.js";
import type { BashProfileSnapshot } from "./legacy-config.js";
import { ghPrCreateHandler, ghPrCreateInterpreterObservers } from "./bash/handlers/command-gh-pr-create.js";
import type { GhPrCreatePolicy } from "./bash/policies/gh-pr-create.js";

export type BashInitialEnvironment =
  | { readonly kind: "unavailable" }
  | { readonly kind: "verified"; readonly values: Readonly<Record<string, string>> }
  | { readonly kind: "filtered"; readonly values: Readonly<Record<string, string>>; readonly unset: readonly string[] };

export interface BashPolicyAnalysisOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  readonly initialEnvironment?: BashInitialEnvironment;
  readonly policies: readonly ValidatedBashPolicy[];
  /** Supplied by live harness adapters; omitted evaluation is offline-safe. */
  readonly cwd?: string;
  readonly executableFilesystem?: ExecutableFilesystem;
}

export interface BashPolicyEvaluation extends PolicyEvaluation {
  readonly events: readonly BashPolicyEvent[];
  readonly analysis: BashPolicyAnalysis;
}

export interface BashAuthorizationAnalysis {
  readonly verdict: AuthorizationVerdict;
  readonly outcome: ReturnType<typeof runSteps>["outcome"];
  readonly evidence: readonly ReturnType<typeof runSteps>["evidence"][number][];
  readonly policy: PolicyEvidence | null;
  readonly policies: readonly PolicyEvidence[];
}

export interface BashGuardOptions extends Omit<BashPolicyAnalysisOptions, "policies" | "cwd" | "executableFilesystem"> {
  readonly ghPrCreatePolicy?: GhPrCreatePolicy;
}

export type BashGuardEvaluation =
  | { readonly kind: "block"; readonly reason: string; readonly policy: PolicyEvidence; readonly policies: readonly PolicyEvidence[] }
  | { readonly kind: "pass"; readonly status: "complete" | "indeterminate" | "failure"; readonly policies: readonly PolicyEvidence[] };

export interface BashConfiguredOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  readonly initialEnvironment?: BashInitialEnvironment;
  readonly profileSnapshot: BashProfileSnapshot;
}

const baseHandlers: readonly PolicyObserver[] = Object.freeze([...readerHandlers, ...httpHandlers, kubectlHandler]);

/** Compatibility facade for adapters which have not yet migrated to loaded policy runtimes. */
export function analyzeBashAuthorization(options: Omit<BashPolicyAnalysisOptions, "policies" | "cwd" | "executableFilesystem"> & { readonly handlers?: readonly PolicyObserver[] }): BashAuthorizationAnalysis {
  const limits = options.limits ?? DEFAULT_BASH_ANALYSIS_LIMITS;
  const parsed = parseBashProgram(options.source);
  const program = parsed.kind === "parse-failure" ? parsed.program : parsed;
  const registry = createCommandRegistry([...baseHandlers, ...(options.handlers ?? [])]);
  const completed = runSteps(walkProgram(program, {
    environment: initialEnvironment(options.initialEnvironment, limits),
    dispatchCommand: (request) => dispatchCommand(request, registry),
    preflightCommand: (request) => preflightCommand(request, registry),
  }, parsed.kind === "parse-failure" ? failure(parsed.span) : undefined), limits);
  const policies = Object.freeze([...(completed.outcome.policies ?? [])]);
  return Object.freeze({ verdict: completed.verdict, outcome: completed.outcome, evidence: Object.freeze([...completed.evidence]), policy: policies[0] ?? null, policies });
}

export function evaluateBashGuards(options: BashGuardOptions): BashGuardEvaluation {
  const handlers = options.ghPrCreatePolicy?.enabled
    ? [ghPrCreateHandler(options.ghPrCreatePolicy), ...ghPrCreateInterpreterObservers] : [];
  const analysis = analyzeBashAuthorization({ ...options, handlers });
  const policy = analysis.policies.find((candidate) => candidate.decision === "deny"
    && ["secret-read", "github-http", "kubectl", "unsupported-shell-source", "gh-pr-create"].includes(candidate.name));
  if (policy) return Object.freeze({ kind: "block", reason: policy.reason ?? `${policy.name} is blocked`, policy, policies: analysis.policies });
  return Object.freeze({ kind: "pass", status: analysis.outcome.kind === "safe" ? "complete" : analysis.outcome.kind === "failure" ? "failure" : "indeterminate", policies: analysis.policies });
}

/** Compatibility profile result. Global policy runtimes remain the authoritative adapter path. */
export function evaluateConfiguredBash(options: BashConfiguredOptions) {
  const analysis = analyzeBashAuthorization(options);
  const guards = evaluateBashGuards(options);
  const kubectl = analysis.policies.filter((policy) => policy.name === "kubectl" && policy.kubectl?.mentionsSecret).map((policy) => Object.freeze({
    kind: "kubectl-secret" as const,
    policy: "kubectl" as const,
    fields: Object.freeze({ kubectl_subcommand: policy.kubectl!.subcommand, resource: policy.kubectl!.resource, command_length: options.source.length }),
  }));
  return Object.freeze({
    guards,
    permission: Object.freeze({ kind: "ignore" as const }),
    profiles: Object.freeze({}),
    analysis: Object.freeze({ status: guards.kind === "pass" ? guards.status : "complete", failure: analysis.outcome.kind === "failure" ? Object.freeze({ budget: analysis.outcome.budget ?? null }) : null, evidence: analysis.policies }),
    audit: Object.freeze({ events: Object.freeze(kubectl) }),
  });
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
    cwd: options.cwd ?? "/",
    executableFilesystem: options.executableFilesystem ?? unavailableExecutableFilesystem,
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
