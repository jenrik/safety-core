import type { SourceSpan } from "../bash/cst.js";
import type { NormalizedRedirect, ResolvedWord } from "../bash/expand.js";
import type { BindingValue } from "../bash/environment.js";
import type { BashExecutionProvenance, ProcessEffect } from "../bash/walker.js";

export type PolicyDiagnosticPart =
  | { readonly kind: "literal"; readonly value: string }
  | { readonly kind: "value"; readonly value: unknown };
export type PolicyTemplateValue = readonly PolicyDiagnosticPart[];

export type PolicyDecision =
  | { readonly kind: "allow"; readonly reason: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
  | { readonly kind: "deny"; readonly reason: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
  | { readonly kind: "defer"; readonly reason?: PolicyTemplateValue }
  | { readonly kind: "ignore" };

/**
 * Stable identity supplied by a loader. Task 2 resolves source paths through
 * the filesystem before constructing this value; evaluation never infers
 * policy semantics from the canonical path.
 */
export interface PolicySourceIdentity {
  readonly canonicalPath: string;
}

/** Open selector data interpreted by the policy's loader or compiler, not the evaluator. */
export interface BashPolicySelector {
  readonly kind: string;
  readonly [key: string]: unknown;
}

/** One fully modeled command invocation, including executable-less redirect forms. */
export interface InvocationView {
  readonly kind: "invocation";
  /** Null for redirect-only commands and redirects owned by compound statements. */
  readonly executable: ResolvedWord | null;
  readonly argv: readonly ResolvedWord[];
  /** Complete modeled bindings, including exact known values and explicit unknowns. */
  readonly environment: Readonly<Record<string, BindingValue>>;
  /** Export state for every materialized binding in the invocation environment. */
  readonly exportedEnvironment?: Readonly<Record<string, boolean>>;
  /** Whether bindings absent from the modeled map are unknown or proven unset. */
  readonly missingBindings: "unknown" | "unset";
  readonly redirects: readonly NormalizedRedirect[];
  /** Command-prefix assignments in source order, represented by their effective bindings. */
  readonly assignments: Readonly<Record<string, BindingValue>>;
  readonly span: SourceSpan;
  readonly provenance: BashExecutionProvenance;
  readonly inPipeline: boolean;
  readonly processEffect: ProcessEffect;
}

/** A reachable execution route the walker could not model as an invocation. */
export interface ExecutionGapView {
  readonly kind: "execution-gap";
  readonly reason: string;
  readonly environment: Readonly<Record<string, BindingValue>>;
  /** Whether bindings absent from the modeled map are unknown or proven unset. */
  readonly missingBindings: "unknown" | "unset";
  readonly span: SourceSpan;
  readonly provenance: BashExecutionProvenance;
  readonly inPipeline: boolean;
  readonly processEffect: ProcessEffect;
}

export type BashPolicyEvent = InvocationView | ExecutionGapView;

/** Policies are pure single-event classifiers; state must not cross evaluations. */
export interface BashPolicy {
  evaluate(event: BashPolicyEvent): PolicyDecision;
}

export type GuardPolicyDecision = Exclude<PolicyDecision, { readonly kind: "allow" }>;

export interface LoadedBashPolicy {
  readonly source: PolicySourceIdentity;
  readonly layer: "guard" | "permission";
  readonly select: readonly BashPolicySelector[];
  evaluate(event: BashPolicyEvent): PolicyDecision;
}

/** A guard may never grant permission. */
export interface GuardBashPolicy extends Omit<LoadedBashPolicy, "layer" | "evaluate"> {
  readonly layer: "guard";
  evaluate(event: BashPolicyEvent): GuardPolicyDecision;
}

/** A permission policy may return any policy decision. */
export interface PermissionBashPolicy extends Omit<LoadedBashPolicy, "layer"> {
  readonly layer: "permission";
}

/** Policies accepted by loading validation and request evaluation. */
export type ValidatedBashPolicy = GuardBashPolicy | PermissionBashPolicy;

/** Whether traversal completed every reachable path before policy aggregation. */
export interface BashPolicyAnalysis {
  readonly complete: boolean;
}

/** One unredacted policy observation retained for adapter and explain consumers. */
export interface PolicyTrace {
  readonly source: PolicySourceIdentity;
  readonly layer: LoadedBashPolicy["layer"];
  readonly event: BashPolicyEvent;
  readonly decision: PolicyDecision;
}

export interface PolicyEvaluation {
  readonly decision: "allow" | "deny" | "defer";
  readonly traces: readonly PolicyTrace[];
}
