import type { BashCommand, BashRedirectKind, BashWord, SourceSpan } from "./cst.js";
import {
  assignBinding,
  beginCommandOverlay,
  known,
  lookupBinding,
  unknown,
  type Environment,
  type EnvironmentPatch,
} from "./environment.js";

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
}

export interface ResolvedUnknownWord {
  readonly kind: "unknown";
  readonly reason: ExpansionUnknownReason;
}

export type ResolvedWord = ResolvedKnownWord | ResolvedUnknownWord;

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
      return unresolved("command-substitution", word.span);
    case "unsupported-word":
      return unresolved("unsupported-word", word.span);
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
 * receive an overlay; assignment-only commands return a persistent patch.
 */
export function normalizeCommand(command: BashCommand, environment: Environment): NormalizedCommand {
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
    writes.push(assignment.name);
  }

  const effectiveEnvironment = hasInvocation ? assignmentEnvironment : environment;
  const [executableWord, ...argumentWords] = command.words;
  const executable = executableWord ? expandWordInContext(executableWord, effectiveEnvironment, "executable") : null;
  const argv = argumentWords.map((word) => expandWordInContext(word, effectiveEnvironment, "argument"));
  const redirects = command.redirects.map((redirect) => freeze({
    kind: redirect.kind,
    target: redirect.target ? expandWordInContext(redirect.target, effectiveEnvironment, "redirect") : null,
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
  let quote: "single" | "double" | null = null;

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
        return unresolved("carriage-return-continuation", span);
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
      return unresolved("process-substitution", span);
    }
    if (quote !== "single" && character === "`") return unresolved("command-substitution", span);
    if (quote === null && (character === "*" || character === "?" || character === "[")) {
      return unresolved("globbing", span);
    }
    if (quote !== "single" && character === "$") {
      const expansion = expandVariableAt(text, index, span, environment, context, quote === "double");
      if (expansion.kind === "unknown") return expansion;
      value += expansion.value.value;
      index = expansion.next;
      continue;
    }
    if (quote === null && character === "~") return unresolved("tilde-expansion", span);
    if (quote === null && character === "{") return unresolved("brace-expansion", span);

    value += character;
    index++;
  }

  return resolvedKnown(value);
}

function expandVariableAt(
  text: string,
  start: number,
  span: SourceSpan,
  environment: Environment,
  context: WordContext,
  quoted: boolean,
): { readonly kind: "known"; readonly value: ResolvedKnownWord; readonly next: number } | ResolvedUnknownWord {
  const next = text[start + 1];
  if (next === "(") {
    return unresolved(text[start + 2] === "(" ? "arithmetic-expansion" : "command-substitution", span);
  }
  if (next === "{") {
    const close = text.indexOf("}", start + 2);
    if (close < 0) return unresolved("unsupported-parameter-expansion", span);
    const content = text.slice(start + 2, close);
    if (content.startsWith("!")) return unresolved("indirect-expansion", span, variablePrefix(content.slice(1)));
    if (content.includes("[")) return unresolved("array-expansion", span, variablePrefix(content));
    if (!isVariableName(content)) return unresolved("unsupported-parameter-expansion", span, variablePrefix(content));
    return resolveVariable(content, span, environment, close + 1, context, quoted);
  }
  if (!next || !isVariableStart(next)) {
    return unresolved("unsupported-dollar-expansion", span);
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
): { readonly kind: "known"; readonly value: ResolvedKnownWord; readonly next: number } | ResolvedUnknownWord {
  const binding = lookupBinding(environment, variable).value;
  if (binding.kind !== "known") return unresolved("unknown-variable", span, variable);
  if (!quoted && context !== "assignment" && changesUnquotedWordShape(binding.value, environment)) {
    return unresolved("unquoted-expansion", span, variable);
  }
  return { kind: "known", value: resolvedKnown(binding.value), next };
}

function unsupportedPart(word: BashWord): ResolvedUnknownWord | undefined {
  switch (word.kind) {
    case "command-substitution":
      return unresolved("command-substitution", word.span);
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

function unresolved(kind: ExpansionUnknownReason["kind"], span: SourceSpan, variable?: string): ResolvedUnknownWord {
  return freeze({
    kind: "unknown",
    reason: freeze({
      kind,
      span: freeze({ start: span.start, end: span.end }),
      ...(variable ? { variable } : {}),
    }),
  });
}

function resolvedKnown(value: string): ResolvedKnownWord {
  return freeze({ kind: "known", value });
}

function isVariableName(value: string): boolean {
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
