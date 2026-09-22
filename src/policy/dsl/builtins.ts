/** The closed builtin catalogue for safety-core/bash-policy-v1. */
export type BuiltinValueType =
  | "bool"
  | "count"
  | "string"
  | "stringish"
  | "string-set"
  | "input-ref"
  | "tuple"
  | "json"
  | "environment-value"
  | "url"
  | "repository";

export interface BuiltinDefinition {
  readonly args: readonly BuiltinValueType[];
  readonly result: BuiltinValueType;
  readonly total: true;
  /** Complexity in the total size of the supplied operands. */
  readonly complexity: string;
  readonly purpose: string;
}

const builtin = (
  args: readonly BuiltinValueType[],
  result: BuiltinValueType,
  complexity: string,
  purpose: string,
): BuiltinDefinition => Object.freeze({ args: Object.freeze([...args]), result, total: true as const, complexity, purpose });

/**
 * Only operations required by the Task 4-5 policy corpus are present here.
 * Adding an operation changes the v1 language and requires a new reviewed
 * catalogue entry, totality argument, and author documentation.
 */
export const BUILTINS_V1: Readonly<Record<string, BuiltinDefinition>> = Object.freeze({
  equals: builtin(["stringish", "stringish"], "bool", "O(n)", "Exact string equality."),
  inStringSet: builtin(["stringish", "string-set"], "bool", "O(n + s)", "Exact membership in a finite literal string set."),
  asciiLower: builtin(["stringish"], "string", "O(n)", "ASCII-only lower-case conversion."),
  asciiUpper: builtin(["stringish"], "string", "O(n)", "ASCII-only upper-case conversion."),
  equalsAsciiCaseInsensitive: builtin(["stringish", "stringish"], "bool", "O(n)", "ASCII case-insensitive equality."),
  wordInAsciiCaseInsensitiveSet: builtin(["stringish", "string-set"], "bool", "O(n + s)", "ASCII case-insensitive finite-set membership."),
  startsWith: builtin(["stringish", "stringish"], "bool", "O(n)", "Prefix test."),
  endsWith: builtin(["stringish", "stringish"], "bool", "O(n)", "Suffix test."),
  includes: builtin(["stringish", "stringish"], "bool", "O(nm)", "Substring test."),
  basename: builtin(["stringish"], "string", "O(n)", "Lexical final non-empty slash-delimited path component."),
  pathComponent: builtin(["stringish", "count"], "string", "O(n)", "Lexical slash-delimited component at a bounded literal index."),
  pathAfterComponents: builtin(["stringish", "count"], "string", "O(n)", "Suffix after a fixed number of slash-delimited components, preserving remaining separators."),
  splitComponent: builtin(["stringish", "string", "count"], "string", "O(n)", "Fixed-delimiter component at a bounded literal index."),
  leadingAsciiDigits: builtin(["stringish"], "string", "O(n)", "Leading ASCII decimal-digit prefix."),
  parseBoundedInt: builtin(["stringish", "count"], "count", "O(n)", "Decimal integer parsing saturated to the supplied bound."),
  boundedIntAtMost: builtin(["count", "count"], "bool", "O(1)", "Bounded integer comparison."),
  safeGlob: builtin(["stringish", "string"], "bool", "O(nm)", "Glob matching with only literal, ?, and * tokens."),
  anySafeGlob: builtin(["stringish", "string-set"], "bool", "O(nms)", "Finite disjunction of safe glob patterns."),
  linearRegex: builtin(["stringish", "string"], "bool", "O(n + m)", "Restricted linear regular-expression match without groups, alternation, lookaround, or backreferences."),
  parseUrl: builtin(["stringish"], "url", "O(n)", "Strict URL decomposition without network access."),
  urlHostEquals: builtin(["url", "string"], "bool", "O(n)", "Exact ASCII-normalized URL host equality."),
  parseRepository: builtin(["stringish"], "repository", "O(n)", "Strict owner/repository identifier parsing."),
  repositoryEquals: builtin(["repository", "string", "string"], "bool", "O(n)", "Exact parsed repository comparison."),
  normalizeKubernetesResource: builtin(["stringish"], "string", "O(n)", "ASCII normalization of Kubernetes resource singular/plural aliases."),
  normalizeGitHubEndpoint: builtin(["stringish"], "string", "O(n)", "Lexical normalization of a GitHub API endpoint path."),
  environmentLookup: builtin(["string"], "environment-value", "O(n)", "Known/unknown/absent event environment lookup."),
  environmentIsPresent: builtin(["environment-value"], "bool", "O(1)", "Environment presence predicate."),
  environmentIsKnown: builtin(["environment-value"], "bool", "O(1)", "Known environment value predicate."),
  environmentIsUnknown: builtin(["environment-value"], "bool", "O(1)", "Unknown environment value predicate."),
  environmentValueEquals: builtin(["environment-value", "string"], "bool", "O(n)", "Exact known environment value comparison."),
  environmentIsExported: builtin(["string"], "bool", "O(1)", "Known exported-environment proof predicate."),
  missingEnvironmentMayBePresent: builtin([], "bool", "O(1)", "Whether event-absent environment bindings are unknown rather than proven unset."),
  redirectHasInputPath: builtin(["stringish"], "bool", "O(r + n)", "Input redirect path predicate."),
  hasAssignment: builtin(["string"], "bool", "O(a)", "Exact leading assignment-name predicate."),
  hasProvenanceRoute: builtin(["string"], "bool", "O(p)", "Exact execution provenance route membership."),
  isInPipeline: builtin([], "bool", "O(1)", "Pipeline-context predicate."),
  processEffectIs: builtin(["string"], "bool", "O(1)", "Exact process-effect predicate."),
  urlHost: builtin(["url"], "string", "O(1)", "Parsed URL hostname."),
  urlPath: builtin(["url"], "string", "O(1)", "Parsed URL path without query or fragment."),
  inputIsBindingResolved: builtin(["stringish"], "bool", "O(1)", "Whether an immutable input word came from a resolved binding."),
  inputBlockedDomain: builtin(["stringish"], "string", "O(1)", "Blocked-domain metadata on an immutable unresolved input word."),
  domainToken: builtin(["stringish", "string"], "bool", "O(nm)", "ASCII case-insensitive domain token match with hostname-boundary semantics."),
});

export function builtinDefinition(name: string): BuiltinDefinition | undefined {
  return BUILTINS_V1[name];
}
