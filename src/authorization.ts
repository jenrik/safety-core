import { createCommandRegistry, dispatchCommand, ignorePolicy, preflightCommand, type PolicyObserver } from "./bash/dispatch.js";
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
import { ghApiHandler } from "./bash/handlers/command-gh-api.js";
import { ghReadOnlyHandler } from "./bash/handlers/command-gh-read-only.js";
import { ghPrCreateHandler, ghPrCreateInterpreterObservers } from "./bash/handlers/command-gh-pr-create.js";
import { straceReadOnlyHandler } from "./bash/handlers/command-strace-read-only.js";
import { isGhPrCreateCommand } from "./bash/handlers/gh-command-line.js";
import { genericReadOnlyHandlers, helmReadOnlyHandlers, strictReadOnlyHandlers } from "./bash/handlers/read-only.js";
import { STRICT_BASH_PROFILE_EXECUTABLES, type BashProfileSnapshot, type StrictBashProfile } from "./legacy-config.js";
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

type BashPermissionProfile = "readOnlyBash" | "ghApiReadOnly" | "ghReadOnly" | "helmReadOnly" | StrictBashProfile | "ghPrCreate";
type BashConfiguredPermissionDecision =
  | { readonly kind: "allow"; readonly profile: BashPermissionProfile; readonly reason: string }
  | { readonly kind: "deny"; readonly profile: BashPermissionProfile; readonly reason: string }
  | { readonly kind: "defer" }
  | { readonly kind: "ignore" };

const baseHandlers: readonly PolicyObserver[] = Object.freeze([...readerHandlers, ...httpHandlers, kubectlHandler]);

/** Compatibility facade for adapters which have not yet migrated to loaded policy runtimes. */
export function analyzeBashAuthorization(options: Omit<BashPolicyAnalysisOptions, "policies" | "cwd" | "executableFilesystem"> & { readonly handlers?: readonly PolicyObserver[]; readonly includeBaseHandlers?: boolean }): BashAuthorizationAnalysis {
  const limits = options.limits ?? DEFAULT_BASH_ANALYSIS_LIMITS;
  const parsed = parseBashProgram(options.source);
  const program = parsed.kind === "parse-failure" ? parsed.program : parsed;
  const registry = createCommandRegistry([...(options.includeBaseHandlers === false ? [] : baseHandlers), ...(options.handlers ?? [])]);
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
  const snapshot = options.profileSnapshot;
  const analysis = analyzeBashAuthorization({ ...options, limits: options.limits ?? snapshot.limits, handlers: configuredHandlers(snapshot), includeBaseHandlers: false });
  const guards = guardEvaluation(analysis);
  const kubectl = analysis.policies.filter((policy) => policy.name === "kubectl" && policy.kubectl?.mentionsSecret).map((policy) => Object.freeze({
    kind: "kubectl-secret" as const,
    policy: "kubectl" as const,
    fields: Object.freeze({ kubectl_subcommand: policy.kubectl!.subcommand, resource: policy.kubectl!.resource, command_length: options.source.length }),
  }));
  return Object.freeze({
    guards,
    permission: selectPermission(snapshot, profileDecisions(snapshot, analysis)),
    profiles: profileDecisions(snapshot, analysis),
    analysis: Object.freeze({ status: guards.kind === "pass" ? guards.status : "complete", failure: analysis.outcome.kind === "failure" ? Object.freeze({ budget: analysis.outcome.budget ?? null }) : null, evidence: analysis.policies }),
    audit: Object.freeze({ events: Object.freeze(kubectl) }),
  });
}

function configuredHandlers(snapshot: BashProfileSnapshot): readonly PolicyObserver[] {
  const handlers: PolicyObserver[] = [...baseHandlers];
  if (snapshot.readOnlyBash) handlers.push(...genericReadOnlyHandlers);
  if (snapshot.ghReadOnly) handlers.push(straceReadOnlyHandler, snapshot.ghPrCreate.enabled ? configuredGhReadOnlyHandler : ghReadOnlyHandler);
  if (snapshot.helmReadOnly) handlers.push(...helmReadOnlyHandlers);
  for (const [profile, executable] of STRICT_BASH_PROFILE_EXECUTABLES) if (snapshot.strictProfiles[profile]) handlers.push(...strictReadOnlyHandlers(executable));
  if (snapshot.ghApiReadOnly) handlers.push(ghApiHandler);
  if (snapshot.ghPrCreate.enabled) handlers.push(ghPrCreateHandler(snapshot.ghPrCreate), ...ghPrCreateInterpreterObservers);
  return Object.freeze([...new Set(handlers)]);
}

const configuredGhReadOnlyHandler: PolicyObserver = Object.freeze({
  name: "gh",
  observe(cursor, context) { return isGhPrCreateCommand(cursor.invocation.argv.filter((word) => word.kind === "known").map((word) => word.value)) ? ignorePolicy() : ghReadOnlyHandler.observe(cursor, context); },
});

function profileDecisions(snapshot: BashProfileSnapshot, analysis: BashAuthorizationAnalysis): Readonly<Record<BashPermissionProfile, BashConfiguredPermissionDecision>> {
  return Object.freeze(Object.fromEntries(enabledProfiles(snapshot).map((profile) => [profile, profileDecision(profile, analysis)]))) as Readonly<Record<BashPermissionProfile, BashConfiguredPermissionDecision>>;
}
function profileDecision(profile: BashPermissionProfile, analysis: BashAuthorizationAnalysis): BashConfiguredPermissionDecision {
  const own = analysis.policies.filter((policy) => belongsToProfile(policy, profile));
  const sharedDefer = analysis.policies.some((policy) => policy.name === "generic-read-only" && policy.decision === "defer" && (policy.readOnly?.tool === "strace" || policy.readOnly?.tool === "dynamic-executable"));
  if (own.length === 0) return sharedDefer || analysis.outcome.kind === "failure" ? Object.freeze({ kind: "defer" }) : Object.freeze({ kind: "ignore" });
  const denied = own.find((policy) => policy.decision === "deny");
  if (denied) return Object.freeze({ kind: "deny", profile, reason: denied.reason ?? `${profile} denied the Bash command` });
  const ownSpans = new Set(own.map(policySpan));
  const foreign = analysis.policies.some((policy) => !belongsToProfile(policy, profile) && (!isBaselineEvidence(policy) || !ownSpans.has(policySpan(policy))));
  if (sharedDefer || foreign || own.some((policy) => policy.decision !== "allow") || analysis.verdict.kind !== "allow") return Object.freeze({ kind: "defer" });
  return Object.freeze({ kind: "allow", profile, reason: own[0]!.reason ?? `${profile} auto-allowed the Bash command` });
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
  for (const profile of enabledProfiles(snapshot)) if (profiles[profile]?.kind === "deny") return profiles[profile]!;
  for (const profile of enabledProfiles(snapshot)) if (profiles[profile] && profiles[profile]!.kind !== "ignore") return profiles[profile]!;
  return Object.freeze({ kind: "ignore" });
}
function belongsToProfile(policy: PolicyEvidence, profile: BashPermissionProfile): boolean {
  if (profile === "ghPrCreate") return policy.name === "gh-pr-create";
  if (profile === "ghApiReadOnly") return policy.name === "gh-api";
  if (profile === "ghReadOnly") return policy.name === "gh-read-only";
  if (profile === "helmReadOnly") return policy.name === "helm-read-only";
  if (profile === "readOnlyBash") return policy.name === "generic-read-only";
  return policy.name === "strict-read-only" && STRICT_BASH_PROFILE_EXECUTABLES.some(([name, executable]) => name === profile && executable === policy.readOnly?.tool);
}
function isBaselineEvidence(policy: PolicyEvidence): boolean { return ["secret-read", "github-http", "kubectl", "unsupported-shell-source"].includes(policy.name); }
function policySpan(policy: PolicyEvidence): string { return policy.span ? `${policy.span.start}:${policy.span.end}` : "unproven"; }
function guardEvaluation(analysis: BashAuthorizationAnalysis): BashGuardEvaluation {
  const policy = analysis.policies.find((candidate) => candidate.decision === "deny" && ["secret-read", "github-http", "kubectl", "unsupported-shell-source", "gh-pr-create"].includes(candidate.name));
  return policy ? Object.freeze({ kind: "block", reason: policy.reason ?? `${policy.name} is blocked`, policy, policies: analysis.policies }) : Object.freeze({ kind: "pass", status: analysis.outcome.kind === "safe" ? "complete" : analysis.outcome.kind === "failure" ? "failure" : "indeterminate", policies: analysis.policies });
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
