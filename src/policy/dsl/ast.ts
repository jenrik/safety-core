import type { BuiltinValueType } from "./builtins.js";

export const POLICY_LANGUAGE_V1 = "safety-core/bash-policy-v1";

export type PolicyLayer = "guard" | "permission";
export type PolicyDecisionKind = "allow" | "deny" | "defer" | "ignore";
export type RegisterType = "bool" | "enum" | "count" | "inputRef" | "tuple";
export type ExpressionType = BuiltinValueType | "unknown";

export interface BoolRegister { readonly type: "bool"; readonly initial: boolean; }
export interface EnumRegister { readonly type: "enum"; readonly values: readonly string[]; readonly initial: string; }
export interface CountRegister { readonly type: "count"; readonly max: number; readonly initial: number; }
export interface InputRefRegister { readonly type: "inputRef"; readonly initial: null; }
export interface TupleRegister { readonly type: "tuple"; readonly items: readonly RegisterDeclaration[]; readonly initial: readonly unknown[]; }
export type RegisterDeclaration = BoolRegister | EnumRegister | CountRegister | InputRefRegister | TupleRegister;

export type Expression =
  | string
  | number
  | boolean
  | null
  | readonly string[]
  | { readonly ref: string }
  | { readonly call: string; readonly args: readonly Expression[] }
  | { readonly all: readonly Expression[] }
  | { readonly any: readonly Expression[] }
  | { readonly not: Expression };

export type TemplatePart = string | Expression;
export type AuditValue = string | number | boolean | null | { readonly ref: string } | { readonly [key: string]: AuditValue } | readonly AuditValue[];

export interface TransitionAction {
  readonly kind: "transition";
  readonly consume: "word";
  readonly next: string;
  readonly set: Readonly<Record<string, Expression>>;
  readonly fold: readonly string[];
}

export interface TerminalAction {
  readonly kind: "terminal";
  readonly decision: PolicyDecisionKind;
  readonly reason?: readonly TemplatePart[];
  readonly suggestion?: readonly TemplatePart[];
  readonly audit?: Readonly<Record<string, AuditValue>>;
}

export type Action = TransitionAction | TerminalAction;
export interface PolicyCase { readonly when: Expression; readonly action: Action; }

export interface StateDeclaration {
  readonly fragments: readonly string[];
  readonly cases: readonly PolicyCase[];
  readonly default: TerminalAction;
  readonly end: TerminalAction;
}

export type OptionValue = "absent" | "required" | "optional";
export type OptionForm = "separate" | "attachedShort" | "equalsLong" | "cluster";
export interface OptionDeclaration {
  readonly names: readonly string[];
  readonly value: OptionValue;
  readonly forms: readonly OptionForm[];
  readonly availableIn: "*" | readonly string[];
  readonly set: Readonly<Record<string, Expression>>;
}

export type FoldCollection = "argv" | "redirects" | "assignments" | "provenance" | "environment";
export type FoldOperation = "any" | "all" | "firstRef" | "lastRef" | "countUpTo";
export interface FoldDeclaration {
  readonly collection: FoldCollection;
  readonly operation: FoldOperation;
  readonly when: Expression;
  readonly limit?: number;
}

export interface FragmentDeclaration {
  readonly uses: readonly string[];
  readonly cases: readonly PolicyCase[];
}

export type Selector =
  | { readonly kind: "invocation" }
  | { readonly kind: "execution-gap"; readonly reason?: string }
  | { readonly executable: { readonly projection: "basename" | "selected-path" | "canonical-target" | "chain-contains"; readonly equals: string } };

export interface ValidationMetrics {
  readonly nodes: number;
  readonly validationWork: number;
  readonly enumDomainChecks: number;
  readonly enumDomainComparisons: number;
  readonly selectors: number;
  readonly states: number;
  readonly transitions: number;
  readonly compiledCases: number;
  readonly literals: number;
  readonly templateParts: number;
  readonly regexBytes: number;
}

export interface PolicyDocument {
  readonly language: typeof POLICY_LANGUAGE_V1;
  readonly layer: PolicyLayer;
  readonly select: readonly Selector[];
  readonly registers: Readonly<Record<string, RegisterDeclaration>>;
  readonly folds: Readonly<Record<string, FoldDeclaration>>;
  readonly options: Readonly<Record<string, OptionDeclaration>>;
  readonly fragments: Readonly<Record<string, FragmentDeclaration>>;
  readonly start: string;
  readonly states: Readonly<Record<string, StateDeclaration>>;
  readonly metrics: ValidationMetrics;
}
