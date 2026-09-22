import type { SourceSpan } from "../bash/cst.js";
import type { NormalizedRedirect, ResolvedWord } from "../bash/expand.js";
import type { BindingValue } from "../bash/environment.js";
import type { BashExecutionProvenance, ProcessEffect } from "../bash/walker.js";
import type { ExecutableIdentity } from "./executable.js";

export type PolicyDiagnosticPart =
  | { readonly kind: "literal"; readonly value: string }
  | { readonly kind: "value"; readonly value: unknown };
export type PolicyTemplateValue = readonly PolicyDiagnosticPart[];

export type PolicyDecision =
  | { readonly kind: "allow"; readonly reason: PolicyTemplateValue; readonly suggestion?: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
  | { readonly kind: "deny"; readonly reason: PolicyTemplateValue; readonly suggestion?: PolicyTemplateValue; readonly audit?: Readonly<Record<string, unknown>> }
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

/** Exact executable selectors supported by code and future DSL policy loaders. */
export type ExecutablePolicySelector =
  | { readonly kind: "executable-basename"; readonly value: string }
  | { readonly kind: "executable-selected-path"; readonly value: string }
  | { readonly kind: "executable-canonical-target"; readonly value: string }
  | { readonly kind: "executable-chain-contains"; readonly value: string }
  | {
    readonly kind: "executable";
    readonly basename?: string;
    readonly selectedPath?: string;
    readonly canonicalTarget?: string;
    readonly chainContains?: string;
  };

/** One fully modeled command invocation, including executable-less redirect forms. */
export interface InvocationView {
  readonly kind: "invocation";
  /** Null for redirect-only commands and redirects owned by compound statements. */
  readonly executable: ResolvedWord | null;
  /** Filesystem-qualified identity; unresolved path facts remain explicit. */
  readonly executableIdentity: ExecutableIdentity;
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

/** A deterministic DSL machine step retained only for explain diagnostics. */
export interface DslPolicyTraceStep {
  readonly state: string;
  readonly argvIndex: number;
  readonly clusterByteIndex: number;
  readonly source: string;
  readonly origin: string;
  readonly action: "transition" | "option" | "terminal" | "end-options";
  readonly folds: readonly string[];
  readonly nextState?: string;
  readonly decision?: PolicyDecision["kind"];
}

export interface TraceableLoadedBashPolicy extends LoadedBashPolicy {
  evaluateWithTrace(event: BashPolicyEvent): { readonly decision: PolicyDecision; readonly steps: readonly DslPolicyTraceStep[] };
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
  readonly dslSteps?: readonly DslPolicyTraceStep[];
}

export interface PolicyEvaluation {
  readonly decision: "allow" | "deny" | "defer";
  readonly traces: readonly PolicyTrace[];
}
