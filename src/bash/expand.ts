import { stripQuotes } from "../shell.js";
import { detectBlockedDomain, isGithubGraphqlEndpoint } from "../github.js";
import type { BashCommand, BashRedirectKind, BashWord, SourceSpan } from "./cst.js";
import {
  assignBinding,
  beginCommandOverlay,
  hasBinding,
  known,
  lookupBinding,
  setExported,
  unknown,
  type Environment,
  type EnvironmentPatch,
} from "./environment.js";
import { isBindingResolvedWord, markBindingResolvedWord } from "./word-provenance.js";

export { isBindingResolvedWord } from "./word-provenance.js";

export interface ResolvedKnownWord {
  readonly kind: "known";
  readonly value: string;
}

export interface ExpansionUnknownReason {
  readonly kind:
    | "unknown-variable"
    | "command-substitution"
    | "process-substitution"
    | "indirect-expansion"
    | "array-expansion"
    | "arithmetic-expansion"
    | "unsupported-parameter-expansion"
    | "unsupported-dollar-expansion"
    | "globbing"
    | "tilde-expansion"
    | "brace-expansion"
    | "unquoted-expansion"
    | "carriage-return-continuation"
    | "unsupported-word";
  readonly span: SourceSpan;
  readonly variable?: string;
  readonly blockedGithubDomain?: string;
  readonly githubGraphqlEndpoint?: true;
}

export interface ResolvedUnknownWord {
  readonly kind: "unknown";
  readonly reason: ExpansionUnknownReason;
}

export type ResolvedWord = ResolvedKnownWord | ResolvedUnknownWord;

export type SymbolicWordFragment =
  | { readonly kind: "literal"; readonly value: string }
  | { readonly kind: "unknown" };

export interface SymbolicWordShape {
  readonly fragments: readonly SymbolicWordFragment[];
  readonly fields: "one" | "one-or-more" | "zero-or-more";
}

const symbolicWordShapes = new WeakMap<ResolvedUnknownWord, SymbolicWordShape>();

/** Internal expansion shape. The WeakMap keeps literal fragments out of serialization. */
export function symbolicWordShape(word: ResolvedWord): SymbolicWordShape | undefined {
  return word.kind === "unknown" ? symbolicWordShapes.get(word) : undefined;
}

export interface NormalizedRedirect {
  readonly kind: BashRedirectKind;
  readonly target: ResolvedWord | null;
}

/** A simple command with a fully static-or-redacted view of each word. */
export interface NormalizedCommand {
  readonly executable: ResolvedWord | null;
  readonly argv: readonly ResolvedWord[];
  readonly redirects: readonly NormalizedRedirect[];
  /** Effective environment for an external invocation, including prefix assignments. */
  readonly environment: Environment;
  /**
   * Assignment writes in source order. For external commands this is a
   * command-local overlay; for assignment-only commands it is persistent.
   */
  readonly assignmentPatch: EnvironmentPatch;
}

/** Build an argv-preserving child invocation without passing through shell syntax. */
export function normalizedInvocation(
  words: readonly ResolvedWord[],
  environment: Environment,
): NormalizedCommand {
  const [executable = null, ...argv] = words;
  return freeze({
    executable,
    argv: freeze(argv),
    redirects: freeze([]),
    environment,
    assignmentPatch: freeze({
      environment,
      writes: readonlySet([]),
    }),
  });
}

/**
 * Resolve only literal text and direct variable references from an explicit
 * environment snapshot. This is deliberately not a shell evaluator.
 */
export function expandWord(word: BashWord, environment: Environment): ResolvedWord {
  return expandWordInContext(word, environment, "argument");
}

type WordContext = "assignment" | "executable" | "argument" | "redirect";

function expandWordInContext(word: BashWord, environment: Environment, context: WordContext): ResolvedWord {
  switch (word.kind) {
    case "command-substitution":
      return symbolicUnknown("command-substitution", word.span, context === "assignment" ? "one" : "zero-or-more");
    case "unsupported-word":
      return symbolicUnknown("unsupported-word", word.span, context === "assignment" ? "one" : "zero-or-more");
    case "word":
    case "expansion":
      return expandStaticText(word.text, word.span, environment, context);
    case "concatenation": {
      const unsupported = unsupportedPart(word);
      return unsupported ?? expandStaticText(word.text, word.span, environment, context);
    }
  }
}

/**
 * Apply assignments left-to-right before resolving a command. Prefix writes
 * receive an overlay, while same-command words expand against the caller.
 */
export function normalizeCommand(
  command: BashCommand,
  environment: Environment,
  sourceDerivedFromBinding = false,
): NormalizedCommand {
  const hasInvocation = command.words.length > 0;
  let assignmentEnvironment = hasInvocation && command.assignments.length > 0
    ? beginCommandOverlay(environment)
    : environment;
  const writes: string[] = [];

  for (const assignment of command.assignments) {
    const resolved = assignment.value
      ? expandWordInContext(assignment.value, assignmentEnvironment, "assignment")
      : resolvedKnown("");
    assignmentEnvironment = assignBinding(assignmentEnvironment, assignment.name, bindingValue(resolved));
    if (hasInvocation) assignmentEnvironment = setExported(assignmentEnvironment, assignment.name, true);
    writes.push(assignment.name);
  }

  const effectiveEnvironment = hasInvocation ? assignmentEnvironment : environment;
  const [executableWord, ...argumentWords] = command.words;
  const executable = executableWord ? retainBindingProvenance(
    expandWordInContext(executableWord, environment, "executable"),
    sourceDerivedFromBinding,
  ) : null;
  const argv = argumentWords.map((word) => retainBindingProvenance(
    expandWordInContext(word, environment, "argument"),
    sourceDerivedFromBinding,
  ));
  const redirects = command.redirects.map((redirect) => freeze({
    kind: redirect.kind,
    target: redirect.target ? retainBindingProvenance(
      expandWordInContext(redirect.target, environment, "redirect"),
      sourceDerivedFromBinding,
    ) : null,
  }));
  const patchEnvironment = assignmentEnvironment;

  return freeze({
    executable,
    argv: freeze(argv),
    redirects: freeze(redirects),
    environment: effectiveEnvironment,
    assignmentPatch: freeze({
      environment: patchEnvironment,
      writes: readonlySet(writes),
    }),
  });
}

function expandStaticText(text: string, span: SourceSpan, environment: Environment, context: WordContext): ResolvedWord {
  let value = "";
  let containsBindingValue = false;
  let quote: "single" | "double" | null = null;
  let firstUnknown: ResolvedUnknownWord | undefined;
  let unknownMaySplit = false;
  const fragments: SymbolicWordFragment[] = [];
  const appendUnknown = (word: ResolvedUnknownWord): void => {
    if (value.length > 0) {
      fragments.push(freeze({ kind: "literal", value }));
      value = "";
    }
    if (fragments.at(-1)?.kind !== "unknown") fragments.push(UNKNOWN_FRAGMENT);
    firstUnknown ??= word;
    unknownMaySplit ||= quote === null && context !== "assignment";
  };

  for (let index = 0; index < text.length;) {
    const character = text[index]!;

    if (character === "\\" && quote === "single") {
      value += character;
      index++;
      continue;
    }
    if (character === "\\") {
      const escaped = text[index + 1];
      if (escaped === "\n") {
        index += 2;
        continue;
      }
      if (escaped === "\r" && text[index + 2] === "\n") {
        appendUnknown(unresolved("carriage-return-continuation", span));
        index += 3;
        continue;
      }
      if (escaped && (quote !== "double" || escaped === "$" || escaped === "\\" || escaped === '"')) {
        value += escaped;
        index += 2;
      } else {
        value += character;
        index++;
      }
      continue;
    }
    if (character === "'" && quote !== "double") {
      quote = quote === "single" ? null : "single";
      index++;
      continue;
    }
    if (character === '"' && quote !== "single") {
      quote = quote === "double" ? null : "double";
      index++;
      continue;
    }
    if (quote !== "single" && (character === "<" || character === ">") && text[index + 1] === "(") {
      appendUnknown(unresolved("process-substitution", span));
      index = expansionEnd(text, index + 1);
      continue;
    }
    if (quote !== "single" && character === "`") {
      appendUnknown(unresolved("command-substitution", span));
      index = backtickEnd(text, index + 1);
      continue;
    }
    if (quote === null && (character === "*" || character === "?" || character === "[")) {
      appendUnknown(unresolved("globbing", span, undefined, detectBlockedDomain(text) ?? undefined, isGithubGraphqlEndpoint(text)));
      index++;
      continue;
    }
    if (quote === null && character === "$" && text[index + 1] === "'") {
      const end = ansiCQuoteEnd(text, index + 2);
      if (end < 0) return unresolved("unsupported-dollar-expansion", span);
      value += stripQuotes(text.slice(index, end + 1));
      index = end + 1;
      continue;
    }
    if (quote !== "single" && character === "$") {
      const expansion = expandVariableAt(text, index, span, environment, context, quote === "double");
      if (expansion.kind === "unknown") appendUnknown(expansion.value);
      else {
        value += expansion.value.value;
        containsBindingValue ||= isBindingResolvedWord(expansion.value);
      }
      index = expansion.next;
      continue;
    }
    if (quote === null && character === "~") {
      appendUnknown(unresolved("tilde-expansion", span));
      index++;
      continue;
    }
    if (quote === null && character === "{" && text[index + 1] !== "}") {
      appendUnknown(unresolved("brace-expansion", span));
      index++;
      continue;
    }

    value += character;
    index++;
  }

  if (!firstUnknown) return resolvedKnown(value, containsBindingValue);
  if (value.length > 0) fragments.push(freeze({ kind: "literal", value }));
  const hasLiteral = fragments.some((fragment) => fragment.kind === "literal" && fragment.value.length > 0);
  return withSymbolicShape(firstUnknown, freeze({
    fragments: freeze(fragments),
    fields: unknownMaySplit ? hasLiteral ? "one-or-more" : "zero-or-more" : "one",
  }));
}

type VariableExpansion =
  | { readonly kind: "known"; readonly value: ResolvedKnownWord; readonly next: number }
  | { readonly kind: "unknown"; readonly value: ResolvedUnknownWord; readonly next: number };

function expandVariableAt(
  text: string,
  start: number,
  span: SourceSpan,
  environment: Environment,
  context: WordContext,
  quoted: boolean,
): VariableExpansion {
  const next = text[start + 1];
  if (next === "(") {
    return {
      kind: "unknown",
      value: unresolved(text[start + 2] === "(" ? "arithmetic-expansion" : "command-substitution", span),
      next: expansionEnd(text, start + 1),
    };
  }
  if (next === "{") {
    const close = text.indexOf("}", start + 2);
    if (close < 0) return { kind: "unknown", value: unresolved("unsupported-parameter-expansion", span), next: text.length };
    const content = text.slice(start + 2, close);
    if (content.startsWith("!")) return { kind: "unknown", value: unresolved("indirect-expansion", span, variablePrefix(content.slice(1))), next: close + 1 };
    if (content.includes("[")) return { kind: "unknown", value: unresolved("array-expansion", span, variablePrefix(content)), next: close + 1 };
    if (!isVariableReference(content)) return { kind: "unknown", value: unresolved("unsupported-parameter-expansion", span, variablePrefix(content)), next: close + 1 };
    return resolveVariable(content, span, environment, close + 1, context, quoted);
  }
  if (next && /[0-9]/.test(next)) {
    return resolveVariable(next, span, environment, start + 2, context, quoted);
  }
  if (!next || !isVariableStart(next)) {
    return { kind: "unknown", value: unresolved("unsupported-dollar-expansion", span), next: Math.min(start + 2, text.length) };
  }

  let end = start + 2;
  while (end < text.length && isVariablePart(text[end]!)) end++;
  return resolveVariable(text.slice(start + 1, end), span, environment, end, context, quoted);
}

function resolveVariable(
  variable: string,
  span: SourceSpan,
  environment: Environment,
  next: number,
  context: WordContext,
  quoted: boolean,
): VariableExpansion {
  const binding = lookupBinding(environment, variable).value;
  if (binding.kind === "unset") {
    if (environment.missingBindings === "unset" || hasBinding(environment, variable)) {
      return { kind: "known", value: resolvedKnown(""), next };
    }
    return { kind: "unknown", value: unresolved("unknown-variable", span, variable), next };
  }
  if (binding.kind !== "known") return { kind: "unknown", value: unresolved("unknown-variable", span, variable), next };
  if (!quoted && context !== "assignment" && changesUnquotedWordShape(binding.value, environment)) {
    return {
      kind: "unknown",
      value: unresolved("unquoted-expansion", span, variable, detectBlockedDomain(binding.value) ?? undefined, isGithubGraphqlEndpoint(binding.value)),
      next,
    };
  }
  return { kind: "known", value: resolvedKnown(binding.value, true), next };
}

function ansiCQuoteEnd(text: string, start: number): number {
  let escaped = false;
  for (let index = start; index < text.length; index++) {
    const character = text[index]!;
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (character === "'") return index;
  }
  return -1;
}

function unsupportedPart(word: BashWord): ResolvedUnknownWord | undefined {
  switch (word.kind) {
    case "command-substitution":
      return undefined;
    case "unsupported-word":
      return unresolved("unsupported-word", word.span);
    case "concatenation":
      for (const part of word.parts) {
        const unsupported = unsupportedPart(part);
        if (unsupported) return unsupported;
      }
      return undefined;
    case "word":
    case "expansion":
      return undefined;
  }
}

function expansionEnd(text: string, opening: number): number {
  let depth = 0;
  let quote: "single" | "double" | null = null;
  let escaped = false;
  for (let index = opening; index < text.length; index++) {
    const character = text[index]!;
    if (escaped) { escaped = false; continue; }
    if (character === "\\" && quote !== "single") { escaped = true; continue; }
    if (character === "'" && quote !== "double") { quote = quote === "single" ? null : "single"; continue; }
    if (character === '"' && quote !== "single") { quote = quote === "double" ? null : "double"; continue; }
    if (quote) continue;
    if (character === "(") depth++;
    if (character === ")" && --depth === 0) return index + 1;
  }
  return text.length;
}

function backtickEnd(text: string, start: number): number {
  let escaped = false;
  for (let index = start; index < text.length; index++) {
    const character = text[index]!;
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (character === "`") return index + 1;
  }
  return text.length;
}

function changesUnquotedWordShape(value: string, environment: Environment): boolean {
  const ifs = lookupBinding(environment, "IFS").value;
  if (ifs.kind === "unknown") return true;
  const delimiters = ifs.kind === "known" ? ifs.value : " \t\n";
  return value.length === 0 || [...delimiters].some((delimiter) => value.includes(delimiter)) || /[*?[]/.test(value);
}

function bindingValue(word: ResolvedWord) {
  return word.kind === "known"
    ? known(word.value)
    : unknown({ kind: word.reason.kind, span: word.reason.span });
}

function unresolved(
  kind: ExpansionUnknownReason["kind"],
  span: SourceSpan,
  variable?: string,
  blockedGithubDomain?: string,
  githubGraphqlEndpoint = false,
): ResolvedUnknownWord {
  return freeze({
    kind: "unknown",
    reason: freeze({
      kind,
      span: freeze({ start: span.start, end: span.end }),
      ...(variable ? { variable } : {}),
      ...(blockedGithubDomain ? { blockedGithubDomain } : {}),
      ...(githubGraphqlEndpoint ? { githubGraphqlEndpoint: true as const } : {}),
    }),
  });
}

function symbolicUnknown(
  kind: ExpansionUnknownReason["kind"],
  span: SourceSpan,
  fields: SymbolicWordShape["fields"],
): ResolvedUnknownWord {
  return withSymbolicShape(unresolved(kind, span), freeze({ fragments: freeze([UNKNOWN_FRAGMENT]), fields }));
}

function withSymbolicShape(word: ResolvedUnknownWord, shape: SymbolicWordShape): ResolvedUnknownWord {
  symbolicWordShapes.set(word, shape);
  return word;
}

const UNKNOWN_FRAGMENT: SymbolicWordFragment = freeze({ kind: "unknown" });

function resolvedKnown(value: string, fromBinding = false): ResolvedKnownWord {
  const result = freeze({ kind: "known" as const, value });
  if (fromBinding) markBindingResolvedWord(result);
  return result;
}

function retainBindingProvenance(word: ResolvedWord, sourceDerivedFromBinding: boolean): ResolvedWord {
  return sourceDerivedFromBinding && word.kind === "known" && !isBindingResolvedWord(word)
    ? resolvedKnown(word.value, true)
    : word;
}

function isVariableReference(value: string): boolean {
  if (/^[0-9]+$/.test(value)) return true;
  return value.length > 0 && isVariableStart(value[0]!) && [...value.slice(1)].every(isVariablePart);
}

function isVariableStart(value: string): boolean {
  return /[A-Za-z_]/.test(value);
}

function isVariablePart(value: string): boolean {
  return /[A-Za-z0-9_]/.test(value);
}

function variablePrefix(value: string): string | undefined {
  const match = /^[A-Za-z_][A-Za-z0-9_]*/.exec(value);
  return match?.[0];
}

function freeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

function readonlySet(values: readonly string[]): ReadonlySet<string> {
  const set = new Set(values);
  return Object.freeze({
    get size(): number { return set.size; },
    has(value: string): boolean { return set.has(value); },
    entries(): SetIterator<[string, string]> { return set.entries(); },
    keys(): SetIterator<string> { return set.keys(); },
    values(): SetIterator<string> { return set.values(); },
    forEach(callbackfn: (value: string, value2: string, set: ReadonlySet<string>) => void, thisArg?: unknown): void {
      set.forEach((value) => callbackfn.call(thisArg, value, value, this));
    },
    [Symbol.iterator](): SetIterator<string> { return set[Symbol.iterator](); },
  });
}
