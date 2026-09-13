import type { SourceSpan } from "./cst.js";

export type AnalysisBudget =
  | "max-function-depth"
  | "max-nested-script-depth"
  | "max-steps"
  | "max-work-items";

export interface SafeOutcome {
  readonly kind: "safe";
  readonly policy?: PolicyEvidence;
  readonly policies?: readonly PolicyEvidence[];
}

export interface IndeterminateOutcome {
  readonly kind: "indeterminate";
  readonly span: SourceSpan;
  readonly policy?: PolicyEvidence;
  readonly policies?: readonly PolicyEvidence[];
}

/** Redacted analysis evidence. It intentionally contains no input values. */
export interface FailureOutcome {
  readonly kind: "failure";
  readonly reason: "analysis-failure";
  readonly span: SourceSpan;
  readonly budget?: AnalysisBudget;
  readonly policies?: readonly PolicyEvidence[];
}

export interface DenyOutcome {
  readonly kind: "deny";
  readonly span: SourceSpan;
  readonly policy?: PolicyEvidence;
  readonly policies?: readonly PolicyEvidence[];
}

export type Outcome = SafeOutcome | IndeterminateOutcome | FailureOutcome | DenyOutcome;

/** Vetted policy metadata; never carry raw argv, environments, or source text. */
export interface PolicyEvidence {
  readonly name: "secret-read" | "github-http" | "kubectl" | "gh-api" | "gh-pr-create" | "gh-read-only" | "helm-read-only" | "strict-read-only";
  readonly decision: "allow" | "deny" | "defer";
  readonly reason?: string;
  readonly kubectl?: {
    readonly subcommand: string | null;
    readonly resource: string | null;
    readonly secretReview: boolean;
    readonly mentionsSecret: boolean;
  };
  readonly readOnly?: {
    readonly tool: string;
  };
}

export type AuthorizationVerdict =
  | { readonly kind: "allow" }
  | { readonly kind: "neutral" }
  | { readonly kind: "deny"; readonly span: SourceSpan };

type OutcomeLog =
  | { readonly kind: "empty" }
  | { readonly kind: "append"; readonly previous: OutcomeLog; readonly outcome: Outcome }
  | { readonly kind: "concat"; readonly parts: readonly OutcomeLog[] };

/** Compact walker evidence. Plain safe outcomes are the identity. */
export interface OutcomeSummary {
  readonly strongest: Outcome;
  readonly events: OutcomeLog;
}

const SAFE: SafeOutcome = Object.freeze({ kind: "safe" });
const ALLOW: AuthorizationVerdict = Object.freeze({ kind: "allow" });
const NEUTRAL: AuthorizationVerdict = Object.freeze({ kind: "neutral" });
const EMPTY_OUTCOME_LOG: OutcomeLog = Object.freeze({ kind: "empty" });
const EMPTY_OUTCOME_SUMMARY: OutcomeSummary = Object.freeze({ strongest: SAFE, events: EMPTY_OUTCOME_LOG });

export function safe(): SafeOutcome {
  return SAFE;
}

export function emptyOutcomeSummary(): OutcomeSummary {
  return EMPTY_OUTCOME_SUMMARY;
}

/** Add one outcome without retaining ordinary safe observations or copying prior evidence. */
export function appendOutcomeSummary(summary: OutcomeSummary, outcome: Outcome): OutcomeSummary {
  if (summary.strongest.kind === "deny") return summary;
  const candidate = redactOutcome(outcome);
  const strongest = selectStrongest(summary.strongest, candidate);
  if (strongest === summary.strongest && (candidate.policies?.length ?? 0) === 0) return summary;
  return freeze({
    strongest,
    events: freeze({ kind: "append", previous: summary.events, outcome: candidate }),
  });
}

/** Merge path summaries while retaining shared policy prefixes only once. */
export function mergeOutcomeSummaries(summaries: Iterable<OutcomeSummary>): OutcomeSummary {
  let strongest: Outcome = SAFE;
  const events: OutcomeLog[] = [];
  for (const summary of summaries) {
    if (strongest.kind === "deny") break;
    strongest = selectStrongest(strongest, summary.strongest);
    if (summary.events.kind !== "empty") events.push(summary.events);
  }
  if (strongest === SAFE && events.length === 0) return EMPTY_OUTCOME_SUMMARY;
  return freeze({
    strongest,
    events: events.length === 0
      ? EMPTY_OUTCOME_LOG
      : events.length === 1
        ? events[0]!
        : freeze({ kind: "concat", parts: Object.freeze(events) }),
  });
}

export function outcomeSummaryIsDeny(summary: OutcomeSummary): boolean {
  return summary.strongest.kind === "deny";
}

/** Materialize the public outcome once, de-duplicating physically shared log prefixes. */
export function materializeOutcomeSummary(summary: OutcomeSummary): Outcome {
  const outcomes = materializeOutcomes(summary.events);
  return outcomes.length === 0 ? SAFE : strongestOutcome(outcomes);
}

export function policySafe(policy: PolicyEvidence): SafeOutcome {
  const redacted = redactPolicy(policy);
  return freeze({ kind: "safe", policy: redacted, policies: Object.freeze([redacted]) });
}

export function indeterminate(span: SourceSpan): IndeterminateOutcome {
  return freeze({ kind: "indeterminate", span: copySpan(span) });
}

export function policyIndeterminate(span: SourceSpan, policy: PolicyEvidence): IndeterminateOutcome {
  const redacted = redactPolicy(policy);
  return freeze({ kind: "indeterminate", span: copySpan(span), policy: redacted, policies: Object.freeze([redacted]) });
}

export function failure(span: SourceSpan): FailureOutcome {
  return freeze({ kind: "failure", reason: "analysis-failure", span: copySpan(span) });
}

export function analysisFailure(budget: AnalysisBudget, span: SourceSpan): FailureOutcome {
  return freeze({ kind: "failure", reason: "analysis-failure", budget, span: copySpan(span) });
}

export function deny(span: SourceSpan): DenyOutcome {
  return freeze({ kind: "deny", span: copySpan(span) });
}

export function policyDeny(span: SourceSpan, policy: PolicyEvidence): DenyOutcome {
  const redacted = redactPolicy(policy);
  return freeze({ kind: "deny", span: copySpan(span), policy: redacted, policies: Object.freeze([redacted]) });
}

/** Drops caller-owned fields before evidence leaves the analysis boundary. */
export function redactOutcome(outcome: Outcome): Outcome {
  const policies = redactPolicies(outcome);
  switch (outcome.kind) {
    case "safe": return withPolicies(outcome.policy ? policySafe(outcome.policy) : SAFE, policies);
    case "indeterminate": return withPolicies(outcome.policy
      ? policyIndeterminate(outcome.span, outcome.policy)
      : indeterminate(outcome.span), policies);
    case "failure": return withPolicies(isAnalysisBudget(outcome.budget)
      ? analysisFailure(outcome.budget, outcome.span)
      : failure(outcome.span), policies);
    case "deny": return withPolicies(outcome.policy ? policyDeny(outcome.span, outcome.policy) : deny(outcome.span), policies);
  }
}

/** Selects the monotonic evidence with deny > failure > indeterminate > safe. */
export function strongestOutcome(outcomes: Iterable<Outcome>): Outcome {
  let strongest: Outcome = SAFE;
  const policies: PolicyEvidence[] = [];
  for (const outcome of outcomes) {
    const redacted = redactOutcome(outcome);
    policies.push(...(redacted.policies ?? []));
    if (redacted.kind === "deny") return withPolicies(redacted, policies);
    if (rank(redacted) > rank(strongest) || (rank(redacted) === rank(strongest) && "policy" in redacted && redacted.policy)) strongest = redacted;
  }
  return withPolicies(strongest, policies);
}

export function finalize(outcomes: Iterable<Outcome>): AuthorizationVerdict {
  const outcome = strongestOutcome(outcomes);
  if (outcome.kind === "deny") return freeze({ kind: "deny", span: outcome.span });
  return outcome.kind === "safe" ? ALLOW : NEUTRAL;
}

function rank(outcome: Outcome): number {
  switch (outcome.kind) {
    case "safe": return 0;
    case "indeterminate": return 1;
    case "failure": return 2;
    case "deny": return 3;
  }
}

function selectStrongest(current: Outcome, candidate: Outcome): Outcome {
  if (candidate.kind === "deny") return candidate;
  return rank(candidate) > rank(current)
    || (rank(candidate) === rank(current) && "policy" in candidate && candidate.policy)
    ? candidate
    : current;
}

function materializeOutcomes(root: OutcomeLog): readonly Outcome[] {
  const outcomes: Outcome[] = [];
  const visited = new Set<OutcomeLog>();
  const agenda: Array<OutcomeLog | { readonly kind: "emit"; readonly outcome: Outcome }> = [root];
  while (agenda.length > 0) {
    const item = agenda.pop()!;
    if (item.kind === "emit") {
      outcomes.push(item.outcome);
      continue;
    }
    if (visited.has(item)) continue;
    visited.add(item);
    switch (item.kind) {
      case "empty":
        break;
      case "append":
        agenda.push({ kind: "emit", outcome: item.outcome }, item.previous);
        break;
      case "concat":
        for (let index = item.parts.length - 1; index >= 0; index--) agenda.push(item.parts[index]!);
        break;
    }
  }
  return Object.freeze(outcomes);
}

function copySpan(span: SourceSpan): SourceSpan {
  return Object.freeze({ start: span.start, end: span.end });
}

function redactPolicy(policy: PolicyEvidence): PolicyEvidence {
  return freeze({
    name: policy.name,
    decision: policy.decision,
    ...(policy.reason ? { reason: policy.reason } : {}),
    ...(policy.kubectl ? {
      kubectl: freeze({
        subcommand: policy.kubectl.subcommand,
        resource: policy.kubectl.resource,
        secretReview: policy.kubectl.secretReview,
        mentionsSecret: policy.kubectl.mentionsSecret,
      }),
    } : {}),
    ...(policy.readOnly ? { readOnly: freeze({ tool: policy.readOnly.tool }) } : {}),
  });
}

function redactPolicies(outcome: Outcome): readonly PolicyEvidence[] {
  const source = outcome.policies ?? (outcome.policy ? [outcome.policy] : []);
  return Object.freeze(source.map(redactPolicy));
}

function withPolicies<T extends Outcome>(outcome: T, policies: readonly PolicyEvidence[]): T {
  return policies.length === 0
    ? outcome
    : freeze({ ...outcome, policies: Object.freeze([...policies]) }) as T;
}

function isAnalysisBudget(value: unknown): value is AnalysisBudget {
  return value === "max-function-depth"
    || value === "max-nested-script-depth"
    || value === "max-steps"
    || value === "max-work-items";
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
