import { createCommandRegistry, dispatchCommand, preflightCommand, type PolicyObserver } from "./bash/dispatch.js";
import { fromFilteredInitialEnvironment, fromInitialEnvironment, fromVerifiedInitialEnvironment } from "./bash/environment.js";
import { failure, type AnalysisBudget, type AuthorizationVerdict, type PolicyEvidence } from "./bash/outcome.js";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type BashAnalysisLimits, type RunStepsResult } from "./bash/runner.js";
import { walkProgram } from "./bash/walker.js";
import { httpHandlers } from "./bash/handlers/http.js";
import { kubectlHandler } from "./bash/handlers/command-kubectl.js";
import { readerHandlers } from "./bash/handlers/readers.js";
import { ghPrCreateHandler, ghPrCreateInterpreterObservers } from "./bash/handlers/command-gh-pr-create.js";
import { ghReadOnlyHandler } from "./bash/handlers/command-gh-read-only.js";
import { straceReadOnlyHandler } from "./bash/handlers/command-strace-read-only.js";
import { knownArguments } from "./bash/handlers/gh-utils.js";
import { isGhPrCreateCommand } from "./bash/handlers/gh-command-line.js";
import { genericReadOnlyHandlers, helmReadOnlyHandlers, strictReadOnlyHandlers } from "./bash/handlers/read-only.js";
import { ghApiHandler } from "./bash/handlers/command-gh-api.js";
import { ignorePolicy } from "./bash/dispatch.js";
import { STRICT_BASH_PROFILE_EXECUTABLES, type BashProfileSnapshot, type StrictBashProfile } from "./config.js";
import type { GhPrCreatePolicy } from "./bash/policies/gh-pr-create.js";
import { parseBashProgram } from "./shell.js";
import { evaluatePolicyEvents } from "./policy/evaluate.js";
import { projectExecutionGapEvent } from "./policy/events.js";
import type { BashPolicyAnalysis, BashPolicyEvent, PolicyEvaluation, ValidatedBashPolicy } from "./policy/types.js";

export type BashInitialEnvironment =
  | { readonly kind: "unavailable" }
  | { readonly kind: "verified"; readonly values: Readonly<Record<string, string>> }
  | {
    readonly kind: "filtered";
    readonly values: Readonly<Record<string, string>>;
    readonly unset: readonly string[];
  };

export interface BashAuthorizationOptions {
  readonly source: string;
  readonly limits?: BashAnalysisLimits;
  /**
   * A harness may seed inherited variables only from a snapshot it proves is
   * equivalent to the Bash invocation environment. Omission is unavailable.
   */
  readonly initialEnvironment?: BashInitialEnvironment;
  /** Explicit policy handlers define the active profiles for this analysis. */
  readonly handlers?: readonly PolicyObserver[];
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

export type BashGuardPolicyName = "secret-read" | "github-http" | "kubectl" | "unsupported-shell-source" | "gh-pr-create";

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

export interface BashGuardOptions extends Pick<BashAuthorizationOptions, "source" | "limits" | "initialEnvironment"> {
  /** Explicit adapter-loaded restrictive profile; the core never loads config. */
  readonly ghPrCreatePolicy?: GhPrCreatePolicy;
}

export type BashPermissionProfile = "readOnlyBash" | "ghApiReadOnly" | "ghReadOnly" | "helmReadOnly" | StrictBashProfile | "ghPrCreate";

export type BashConfiguredPermissionDecision =
  | { readonly kind: "allow"; readonly profile: BashPermissionProfile; readonly reason: string }
  | { readonly kind: "deny"; readonly profile: BashPermissionProfile; readonly reason: string }
  | { readonly kind: "defer" }
  | { readonly kind: "ignore" };

export interface BashConfiguredEvaluation {
  readonly guards: BashGuardEvaluation;
  readonly permission: BashConfiguredPermissionDecision;
  readonly profiles: Readonly<Record<BashPermissionProfile, BashConfiguredPermissionDecision>>;
  readonly analysis: {
    readonly status: BashGuardAnalysisStatus;
    /** Present only when analysis stopped because of a redacted internal failure. */
    readonly failure: { readonly budget: AnalysisBudget | null } | null;
    readonly evidence: readonly PolicyEvidence[];
  };
  readonly audit: {
    readonly events: readonly BashAuditEvent[];
  };
}

/** Redacted event data which adapters may map to their own audit sinks. */
export interface BashAuditEvent {
  readonly kind: "kubectl-secret";
  readonly policy: "kubectl";
  readonly fields: Readonly<{
    kubectl_subcommand: string | null;
    resource: string | null;
    command_length: number;
  }>;
}

export interface BashConfiguredOptions extends Pick<BashAuthorizationOptions, "source" | "limits" | "initialEnvironment"> {
  readonly profileSnapshot: BashProfileSnapshot;
}

export interface BashPolicyEvaluation extends PolicyEvaluation {
  /** Complete unredacted event trace for the explicitly supplied policies. */
  readonly events: readonly BashPolicyEvent[];
  readonly analysis: BashPolicyAnalysis;
}

export interface BashPolicyAnalysisOptions extends Pick<BashAuthorizationOptions, "source" | "limits" | "initialEnvironment"> {
  readonly policies: readonly ValidatedBashPolicy[];
}

const baseHandlers = Object.freeze([...readerHandlers, ...httpHandlers, kubectlHandler]);

/**
 * Analyze a Bash source string with only an explicit empty initial environment.
 * The core never reads process.env; unresolved ambient references stay neutral.
 */
export function analyzeBashAuthorization(options: BashAuthorizationOptions): BashAuthorizationAnalysis {
  const parsed = parseBashProgram(options.source);
  const program = parsed.kind === "parse-failure" ? parsed.program : parsed;
  const registry = createCommandRegistry([...(options.includeBaseHandlers === false ? [] : baseHandlers), ...(options.handlers ?? [])]);
  const initial = walkProgram(program, {
    environment: initialEnvironment(options.initialEnvironment, toEnvironmentBudgets(options.limits)),
    dispatchCommand: (request) => dispatchCommand(request, registry),
    preflightCommand: (request) => preflightCommand(request, registry),
  }, parsed.kind === "parse-failure" ? failure(parsed.span) : undefined);
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
 * Evaluate loader-validated generic policies in shadow mode. This deliberately
 * shares the existing structural walker and runner, but never replaces legacy
 * adapter profile selection or observer dispatch.
 */
export function analyzeBashWithPolicies(options: BashPolicyAnalysisOptions): BashPolicyEvaluation {
  const limits = options.limits ?? DEFAULT_BASH_ANALYSIS_LIMITS;
  const environment = initialEnvironment(options.initialEnvironment, toEnvironmentBudgets(limits));
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
  // Generic policy aggregation supplies command coverage itself.  A legacy
  // indeterminate result only means no built-in handler claimed an invocation;
  // execution gaps and uncovered events remain non-authorizing below.
  const analysis = Object.freeze({ complete: completed.outcome.kind !== "failure" });
  const evaluated = evaluatePolicyEvents(Object.freeze([...events]), options.policies, analysis);
  return freeze({
    // Core structural denies remain authoritative even when no generic policy
    // denies the projected invocation that triggered them.
    decision: completed.outcome.kind === "deny" ? "deny" : evaluated.decision,
    traces: evaluated.traces,
    events: Object.freeze([...events]),
    analysis,
  });
}

/**
 * Evaluate the always-on Bash guards in one walk. This API deliberately cannot
 * grant permission: anything other than a proven baseline-policy denial passes
 * through to the harness's existing permission and judge handling.
 */
export function evaluateBashGuards(options: BashGuardOptions): BashGuardEvaluation {
  const ghPrCreate = options.ghPrCreatePolicy;
  const analysis = analyzeBashAuthorization({
    source: options.source,
    limits: options.limits,
    initialEnvironment: options.initialEnvironment,
    handlers: [
      ...baseHandlers,
      ...(ghPrCreate?.enabled ? [ghPrCreateHandler(ghPrCreate), ...ghPrCreateInterpreterObservers] : []),
    ],
    includeBaseHandlers: false,
  });
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
 * Evaluate every enabled Bash permission profile in one walk. The result keeps
 * guard, permission, analysis, and audit information separate so guard-safe
 * observations cannot authorize a command.
 */
export function evaluateConfiguredBash(options: BashConfiguredOptions): BashConfiguredEvaluation {
  const snapshot = options.profileSnapshot;
  const limits = options.limits ?? snapshot.limits;
  const handlers = configuredHandlers(snapshot);
  const analysis = analyzeBashAuthorization({
    source: options.source,
    limits,
    initialEnvironment: options.initialEnvironment,
    handlers,
    includeBaseHandlers: false,
  });
  const guards = guardEvaluation(analysis);
  const profiles = profileDecisions(snapshot, analysis);
  return freeze({
    guards,
    permission: selectPermission(snapshot, profiles),
    profiles,
    analysis: freeze({
      status: guardAnalysisStatus(analysis.outcome.kind),
      failure: analysis.outcome.kind === "failure" ? freeze({ budget: analysis.outcome.budget ?? null }) : null,
      evidence: analysis.policies,
    }),
    audit: freeze({
      events: kubectlAuditEvents(options.source, analysis.policies),
    }),
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

function initialEnvironment(initial: BashInitialEnvironment | undefined, budgets: ReturnType<typeof toEnvironmentBudgets>) {
  if (initial?.kind === "verified") return fromVerifiedInitialEnvironment(initial.values, budgets);
  if (initial?.kind === "filtered") return fromFilteredInitialEnvironment(initial.values, initial.unset, budgets);
  return fromInitialEnvironment({}, budgets);
}

function isBashGuardDenyEvidence(policy: PolicyEvidence): policy is BashGuardDenyEvidence {
  return policy.decision === "deny"
    && (policy.name === "secret-read" || policy.name === "github-http" || policy.name === "kubectl" || policy.name === "unsupported-shell-source" || policy.name === "gh-pr-create");
}

function guardEvaluation(analysis: BashAuthorizationAnalysis): BashGuardEvaluation {
  const blocked = analysis.policies.find(isBashGuardDenyEvidence);
  return blocked
    ? freeze({ kind: "block", reason: blocked.reason ?? defaultGuardReason(blocked.name), policy: blocked, policies: analysis.policies })
    : freeze({ kind: "pass", status: guardAnalysisStatus(analysis.outcome.kind), policies: analysis.policies });
}

function configuredHandlers(snapshot: BashProfileSnapshot): readonly PolicyObserver[] {
  const handlers: PolicyObserver[] = [...baseHandlers];
  if (snapshot.readOnlyBash) handlers.push(...genericReadOnlyHandlers);
  if (snapshot.ghReadOnly) handlers.push(straceReadOnlyHandler, snapshot.ghPrCreate.enabled ? configuredGhReadOnlyHandler : ghReadOnlyHandler);
  if (snapshot.helmReadOnly) handlers.push(...helmReadOnlyHandlers);
  for (const [profile, executable] of STRICT_BASH_PROFILE_EXECUTABLES) {
    if (snapshot.strictProfiles[profile]) handlers.push(...strictReadOnlyHandlers(executable));
  }
  if (snapshot.ghApiReadOnly) handlers.push(ghApiHandler);
  if (snapshot.ghPrCreate.enabled) handlers.push(ghPrCreateHandler(snapshot.ghPrCreate), ...ghPrCreateInterpreterObservers);
  return Object.freeze([...new Set(handlers)]);
}

/** The PR overlay owns native `gh pr create`; lower-priority gh reads must not taint it. */
const configuredGhReadOnlyHandler: PolicyObserver = Object.freeze({
  name: "gh",
  observe(cursor, context) {
    const args = knownArguments(cursor);
    if (args && isGhPrCreateCommand(args)) return ignorePolicy();
    return ghReadOnlyHandler.observe(cursor, context);
  },
});

function profileDecisions(snapshot: BashProfileSnapshot, analysis: BashAuthorizationAnalysis): Readonly<Record<BashPermissionProfile, BashConfiguredPermissionDecision>> {
  const enabled = enabledProfiles(snapshot);
  const result = {} as Record<BashPermissionProfile, BashConfiguredPermissionDecision>;
  for (const profile of enabled) result[profile] = profileDecision(profile, analysis);
  return Object.freeze(result);
}

function profileDecision(profile: BashPermissionProfile, analysis: BashAuthorizationAnalysis): BashConfiguredPermissionDecision {
  const own = analysis.policies.filter((policy) => belongsToProfile(policy, profile));
  const sharedDefer = analysis.policies.some((policy) => policy.name === "generic-read-only"
    && policy.decision === "defer"
    && (policy.readOnly?.tool === "strace" || policy.readOnly?.tool === "dynamic-executable"));
  if (own.length === 0) return sharedDefer || analysis.outcome.kind === "failure"
    ? freeze({ kind: "defer" })
    : freeze({ kind: "ignore" });
  const denied = own.find((policy) => policy.decision === "deny");
  if (denied) return freeze({ kind: "deny", profile, reason: denied.reason ?? `${profile} denied the Bash command` });
  const ownSpans = new Set(own.map(policySpan));
  const foreign = analysis.policies.some((policy) => !belongsToProfile(policy, profile)
    && (!isBaselineEvidence(policy) || !ownSpans.has(policySpan(policy))));
  if (sharedDefer || foreign || own.some((policy) => policy.decision !== "allow") || analysis.verdict.kind !== "allow") return freeze({ kind: "defer" });
  const policy = own[0]!;
  return freeze({ kind: "allow", profile, reason: policy.reason ?? `${profile} auto-allowed the Bash command` });
}

function enabledProfiles(snapshot: BashProfileSnapshot): BashPermissionProfile[] {
  const profiles: BashPermissionProfile[] = [];
  if (snapshot.ghPrCreate.enabled) profiles.push("ghPrCreate");
  if (snapshot.ghApiReadOnly) profiles.push("ghApiReadOnly");
  if (snapshot.ghReadOnly) profiles.push("ghReadOnly");
  if (snapshot.readOnlyBash) profiles.push("readOnlyBash");
  if (snapshot.helmReadOnly) profiles.push("helmReadOnly");
  for (const [profile] of STRICT_BASH_PROFILE_EXECUTABLES) if (snapshot.strictProfiles[profile]) profiles.push(profile);
  return profiles;
}

function selectPermission(snapshot: BashProfileSnapshot, profiles: Readonly<Record<BashPermissionProfile, BashConfiguredPermissionDecision>>): BashConfiguredPermissionDecision {
  const enabled = enabledProfiles(snapshot);
  for (const profile of enabled) {
    const decision = profiles[profile];
    if (decision?.kind === "deny") return decision;
  }
  for (const profile of enabled) {
    const decision = profiles[profile];
    if (decision && decision.kind !== "ignore") return decision;
  }
  return freeze({ kind: "ignore" });
}

function belongsToProfile(policy: PolicyEvidence, profile: BashPermissionProfile): boolean {
  if (profile === "ghPrCreate") return policy.name === "gh-pr-create";
  if (profile === "ghApiReadOnly") return policy.name === "gh-api";
  if (profile === "ghReadOnly") return policy.name === "gh-read-only";
  if (profile === "helmReadOnly") return policy.name === "helm-read-only";
  if (profile === "readOnlyBash") return policy.name === "generic-read-only";
  return policy.name === "strict-read-only" && strictExecutables(profile).includes(policy.readOnly?.tool ?? "");
}

function strictExecutables(profile: StrictBashProfile): readonly string[] {
  return STRICT_BASH_PROFILE_EXECUTABLES.filter(([name]) => name === profile).map(([, executable]) => executable);
}

function isBaselineEvidence(policy: PolicyEvidence): boolean {
  return policy.name === "secret-read" || policy.name === "github-http" || policy.name === "kubectl" || policy.name === "unsupported-shell-source";
}

function policySpan(policy: PolicyEvidence): string {
  return policy.span ? `${policy.span.start}:${policy.span.end}` : "unproven";
}

/** Derive the audit-safe kubectl summary from already-redacted policy evidence. */
function kubectlAuditEvents(source: string, policies: readonly PolicyEvidence[]): readonly BashAuditEvent[] {
  return Object.freeze(policies
    .filter((policy) => policy.name === "kubectl" && policy.kubectl?.mentionsSecret)
    .map((policy) => freeze({
      kind: "kubectl-secret" as const,
      policy: "kubectl" as const,
      fields: freeze({
        kubectl_subcommand: policy.kubectl!.subcommand,
        resource: policy.kubectl!.resource,
        command_length: source.length,
      }),
    })));
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
    case "unsupported-shell-source": return "Unsupported shell command source is blocked";
    case "gh-pr-create": return "Pull-request creation is blocked";
  }
}


function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
