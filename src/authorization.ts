import { createCommandRegistry, dispatchCommand, type CommandHandler } from "./bash/dispatch.js";
import { fromInitialEnvironment, fromVerifiedInitialEnvironment } from "./bash/environment.js";
import { indeterminate, type AuthorizationVerdict, type PolicyEvidence } from "./bash/outcome.js";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type BashAnalysisLimits, type RunStepsResult } from "./bash/runner.js";
import { walkProgram } from "./bash/walker.js";
import { httpHandlers } from "./bash/handlers/http.js";
import { kubectlHandler } from "./bash/handlers/command-kubectl.js";
import { readerHandlers } from "./bash/handlers/readers.js";
import { parseBashProgram } from "./shell.js";

export type BashInitialEnvironment =
  | { readonly kind: "unavailable" }
  | { readonly kind: "verified"; readonly values: Readonly<Record<string, string>> };

export interface BashAuthorizationOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  /**
   * A harness may seed inherited variables only from a snapshot it proves is
   * equivalent to the Bash invocation environment. Omission is unavailable.
   */
  readonly initialEnvironment?: BashInitialEnvironment;
  /** Explicit policy handlers define the active profiles for this analysis. */
  readonly handlers?: readonly CommandHandler[];
  /** Compatibility profiles can opt out of unrelated baseline policy handlers. */
  readonly includeBaseHandlers?: boolean;
}

/** Adapter-supplied walker settings, excluding command-specific policy handlers. */
export type BashAuthorizationContext = Pick<
  BashAuthorizationOptions,
  "limits" | "initialEnvironment"
>;

export interface BashAuthorizationAnalysis {
  readonly verdict: AuthorizationVerdict;
  readonly outcome: RunStepsResult["outcome"];
  readonly evidence: readonly RunStepsResult["evidence"][number][];
  /** Vetted policy evidence only; it never exposes normalized argv or environments. */
  readonly policy: PolicyEvidence | null;
  readonly policies: readonly PolicyEvidence[];
}

export type BashGuardPolicyName = "secret-read" | "github-http" | "kubectl";

export type BashGuardAnalysisStatus = "complete" | "indeterminate" | "failure";

export type BashGuardDenyEvidence = PolicyEvidence & {
  readonly name: BashGuardPolicyName;
  readonly decision: "deny";
};

export type BashGuardEvaluation =
  | {
    readonly kind: "block";
    readonly reason: string;
    readonly policy: BashGuardDenyEvidence;
    readonly policies: readonly PolicyEvidence[];
  }
  | {
    readonly kind: "pass";
    readonly status: BashGuardAnalysisStatus;
    readonly policies: readonly PolicyEvidence[];
  };

export type BashGuardOptions = Pick<
  BashAuthorizationOptions,
  "source" | "limits" | "initialEnvironment"
>;

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
    environment: initialEnvironment(options.initialEnvironment, toEnvironmentBudgets(options.limits)),
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

/**
 * Evaluate the always-on Bash guards in one walk. This API deliberately cannot
 * grant permission: anything other than a proven baseline-policy denial passes
 * through to the harness's existing permission and judge handling.
 */
export function evaluateBashGuards(options: BashGuardOptions): BashGuardEvaluation {
  const analysis = analyzeBashAuthorization(options);
  const blocked = analysis.policies.find(isBashGuardDenyEvidence);
  if (blocked) {
    return freeze({
      kind: "block",
      reason: blocked.reason ?? defaultGuardReason(blocked.name),
      policy: blocked,
      policies: analysis.policies,
    });
  }
  return freeze({
    kind: "pass",
    status: guardAnalysisStatus(analysis.outcome.kind),
    policies: analysis.policies,
  });
}


/**
 * Run an adapter-facing evaluator with an explicit unavailable environment and
 * map only the definitive walker verdict onto a native permission status.
 */
export function evaluateBashPermission(
  status: string,
  source: string,
  limits: BashAnalysisLimits,
  evaluator: (options: BashAuthorizationOptions) => { readonly verdict: { readonly kind: string } },
): string {
  const result = evaluator({ source, limits, initialEnvironment: { kind: "unavailable" } });
  return mapBashPermissionStatus(status, result.verdict);
}

/** Preserve the native status unless analysis proves the invocation safe or denied. */
export function mapBashPermissionStatus<T extends string>(status: T, verdict: { readonly kind: string }): T | "allow" | "deny" {
  switch (verdict.kind) {
    case "allow": return "allow";
    case "deny": return "deny";
    default: return status;
  }
}

/** OpenCode's native permission mapping: only definitive walker verdicts override it. */
// TODO: Move all harness permission mapping out of the core; adapters should
// translate a harness-neutral configured evaluator result.
export function mapOpenCodeBashStatus<T extends string>(status: T, verdict: { readonly kind: string }): T | "allow" | "deny" {
  return mapBashPermissionStatus(status, verdict);
}

/** Pi's hard-block phase may stop execution only for a proven denial. */
export function shouldBlockPiBash(verdict: { readonly kind: string }): boolean {
  return verdict.kind === "deny";
}

/** Claude Code hooks emit no decision for analysis uncertainty or failure. */
export function mapClaudeBashDecision(verdict: { readonly kind: string }): "allow" | "deny" | undefined {
  return verdict.kind === "allow" || verdict.kind === "deny" ? verdict.kind : undefined;
}

/** Evaluate a hard-block policy under the same explicit unavailable environment. */
export function shouldHardBlockBash(
  source: string,
  limits: BashAnalysisLimits,
  evaluator: (options: BashAuthorizationOptions) => { readonly verdict: { readonly kind: string } },
): boolean {
  return evaluator({ source, limits, initialEnvironment: { kind: "unavailable" } }).verdict.kind === "deny";
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

function initialEnvironment(initial: BashInitialEnvironment | undefined, budgets: ReturnType<typeof toEnvironmentBudgets>) {
  return initial?.kind === "verified"
    ? fromVerifiedInitialEnvironment(initial.values, budgets)
    : fromInitialEnvironment({}, budgets);
}

function isBashGuardDenyEvidence(policy: PolicyEvidence): policy is BashGuardDenyEvidence {
  return policy.decision === "deny"
    && (policy.name === "secret-read" || policy.name === "github-http" || policy.name === "kubectl");
}

function guardAnalysisStatus(kind: RunStepsResult["outcome"]["kind"]): BashGuardAnalysisStatus {
  if (kind === "safe") return "complete";
  return kind === "failure" ? "failure" : "indeterminate";
}

function defaultGuardReason(name: BashGuardPolicyName): string {
  switch (name) {
    case "secret-read": return "Bash command reads a protected secret file";
    case "github-http": return "Direct GitHub HTTP requests are blocked";
    case "kubectl": return "kubectl command is blocked";
  }
}


function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
