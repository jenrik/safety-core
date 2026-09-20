import { symbolicWordShape, type ResolvedWord } from "./expand.js";

export type OptionValue = "none" | "required";
export type LongOptionResolution = "exact" | "unique-prefix";

export interface OptionSpec {
  readonly id: string;
  readonly short?: readonly string[];
  readonly long?: readonly string[];
  /** Exact whole-word spellings for non-GNU named option syntaxes. */
  readonly exact?: readonly string[];
  /** Restricts which sign may introduce this short option. */
  readonly shortPrefixes?: readonly ("-" | "+")[];
  readonly value: OptionValue;
  readonly attached?: boolean;
  readonly separate?: boolean;
  readonly equals?: boolean;
  /** Immediate consumes its own value; deferred consumes one after the rest of the short cluster. */
  readonly terminal?: "immediate" | "deferred";
}

export interface OptionGrammar {
  readonly options: readonly OptionSpec[];
  readonly longResolution: LongOptionResolution;
  readonly shortPrefixes?: readonly ("-" | "+")[];
  readonly stopAtFirstOperand?: boolean;
}

export interface ScannedOption {
  readonly id: string;
  readonly spelling: string;
  readonly index: number;
  readonly attached: boolean;
  readonly value?: ResolvedWord;
}

export type OptionScanFailureReason =
  | "dynamic-option"
  | "unknown-option"
  | "ambiguous-long-option"
  | "missing-option-value"
  | "unsupported-attached-value"
  | "unsupported-separate-value"
  | "unexpected-option-value"
  | "conflicting-terminal-option";

export type OptionScanResult =
  | {
      readonly kind: "parsed";
      readonly options: readonly ScannedOption[];
      readonly operandIndex: number;
      readonly terminal?: ScannedOption;
    }
  | { readonly kind: "failure"; readonly reason: OptionScanFailureReason };

export type ResolvedLongOption =
  | { readonly kind: "known"; readonly option: string; readonly value?: string }
  | { readonly kind: "ambiguous" }
  | undefined;

export function resolveLongOption(
  argument: string,
  options: readonly string[],
  resolution: LongOptionResolution,
): ResolvedLongOption {
  if (!argument.startsWith("--") || argument === "--") return undefined;
  const equals = argument.indexOf("=");
  const name = equals < 0 ? argument : argument.slice(0, equals);
  const exact = options.includes(name) ? name : undefined;
  const matches = exact ? [exact] : resolution === "unique-prefix" ? options.filter((option) => option.startsWith(name)) : [];
  if (matches.length === 0) return undefined;
  if (matches.length > 1) return Object.freeze({ kind: "ambiguous" });
  return Object.freeze({
    kind: "known",
    option: matches[0]!,
    ...(equals < 0 ? {} : { value: argument.slice(equals + 1) }),
  });
}

/** Declaratively scans reviewed short/long option grammars without retaining failure values. */
export function scanOptions(arguments_: readonly ResolvedWord[], grammar: OptionGrammar): OptionScanResult {
  const scanned: ScannedOption[] = [];
  const shortPrefixes = grammar.shortPrefixes ?? ["-"];
  let index = 0;
  while (index < arguments_.length) {
    const word = arguments_[index]!;
    if (word.kind !== "known") {
      const symbolic = scanSymbolicOption(word, grammar, index);
      if (symbolic.kind === "failure") return symbolic;
      if (symbolic.kind === "operand") return grammar.stopAtFirstOperand === false
        ? failure("unknown-option")
        : parsed(scanned, index);
      scanned.push(...symbolic.options);
      index++;
      if (symbolic.terminal) return parsed(scanned, index, symbolic.terminal);
      continue;
    }
    const argument = word.value;
    if (argument === "--") return parsed(scanned, index + 1);

    const exact = grammar.options.find((candidate) => candidate.exact?.includes(argument));
    if (exact) {
      const consumed = consumeOptionValue(exact, argument, undefined, arguments_, index);
      if (consumed.kind === "failure") return consumed;
      scanned.push(consumed.option);
      index += consumed.consumed;
      if (exact.terminal === "immediate") return parsed(scanned, index, consumed.option);
      continue;
    }

    if (argument.startsWith("--")) {
      const resolved = resolveLong(argument, grammar);
      if (resolved.kind === "failure") return resolved;
      const consumed = consumeOptionValue(resolved.spec, resolved.spelling, resolved.attachedValue, arguments_, index);
      if (consumed.kind === "failure") return consumed;
      scanned.push(consumed.option);
      index += consumed.consumed;
      if (resolved.spec.terminal === "immediate") return parsed(scanned, index, consumed.option);
      continue;
    }

    const prefix = argument[0] as "-" | "+" | undefined;
    if (prefix && shortPrefixes.includes(prefix) && argument.length > 1) {
      const cluster = argument.slice(1);
      let offset = 0;
      let deferred: { readonly spec: OptionSpec; readonly spelling: string; readonly optionIndex: number } | undefined;
      while (offset < cluster.length) {
        const spelling = cluster[offset]!;
        const spec = grammar.options.find((candidate) => candidate.short?.includes(spelling));
        if (!spec || (spec.shortPrefixes && !spec.shortPrefixes.includes(prefix))) return failure("unknown-option");
        if (spec.terminal === "deferred") {
          if (deferred) return failure("conflicting-terminal-option");
          deferred = { spec, spelling: `${prefix}${spelling}`, optionIndex: scanned.length };
          scanned.push(Object.freeze({ id: spec.id, spelling: `${prefix}${spelling}`, index, attached: false }));
          offset++;
          if (offset === cluster.length) index++;
          continue;
        }
        const remainder = cluster.slice(offset + 1);
        const consumed = consumeOptionValue(
          spec,
          `${prefix}${spelling}`,
          spec.value === "required" ? remainder || undefined : undefined,
          arguments_,
          index,
        );
        if (consumed.kind === "failure") return consumed;
        scanned.push(consumed.option);
        if (spec.value === "required") {
          index += consumed.consumed;
          if (spec.terminal === "immediate") return parsed(scanned, index, consumed.option);
          break;
        }
        offset++;
        if (spec.terminal === "immediate") return parsed(scanned, index + 1, consumed.option);
        if (offset === cluster.length) index++;
      }
      if (deferred) {
        const value = arguments_[index];
        if (!value) return failure("missing-option-value");
        const terminal = Object.freeze({
          id: deferred.spec.id,
          spelling: deferred.spelling,
          index: scanned[deferred.optionIndex]!.index,
          attached: false,
          value,
        });
        scanned[deferred.optionIndex] = terminal;
        return parsed(scanned, index + 1, terminal);
      }
      continue;
    }

    return grammar.stopAtFirstOperand === false ? failure("unknown-option") : parsed(scanned, index);
  }
  return parsed(scanned, index);
}

function scanSymbolicOption(
  word: Extract<ResolvedWord, { readonly kind: "unknown" }>,
  grammar: OptionGrammar,
  index: number,
):
  | { readonly kind: "options"; readonly options: readonly ScannedOption[]; readonly terminal?: ScannedOption }
  | { readonly kind: "operand" }
  | { readonly kind: "failure"; readonly reason: OptionScanFailureReason } {
  const shape = symbolicWordShape(word);
  if (!shape || shape.fields === "zero-or-more") return failure("dynamic-option");
  let prefix = "";
  for (const fragment of shape.fragments) {
    if (fragment.kind === "unknown") break;
    prefix += fragment.value;
  }
  if (prefix.length === 0) return failure("dynamic-option");
  if (!prefix.startsWith("-") && !prefix.startsWith("+")) return { kind: "operand" };

  if (prefix.startsWith("--")) {
    const equals = prefix.indexOf("=");
    if (equals < 0) return failure("dynamic-option");
    const resolved = resolveLongOption(
      prefix.slice(0, equals),
      grammar.options.flatMap((spec) => spec.long ?? []),
      grammar.longResolution,
    );
    if (!resolved || resolved.kind === "ambiguous") return failure(resolved?.kind === "ambiguous" ? "ambiguous-long-option" : "dynamic-option");
    const spec = grammar.options.find((candidate) => candidate.long?.includes(resolved.option))!;
    if (spec.value !== "required" || spec.equals !== true) return failure("dynamic-option");
    const option = Object.freeze({ id: spec.id, spelling: resolved.option, index, attached: true, value: word });
    return spec.terminal === "immediate"
      ? { kind: "options", options: Object.freeze([option]), terminal: option }
      : { kind: "options", options: Object.freeze([option]) };
  }

  const shortPrefixes = grammar.shortPrefixes ?? ["-"];
  const sign = prefix[0] as "-" | "+";
  if (!shortPrefixes.includes(sign) || prefix.length === 1) return failure("dynamic-option");
  const options: ScannedOption[] = [];
  const cluster = prefix.slice(1);
  for (let offset = 0; offset < cluster.length; offset++) {
    const spelling = cluster[offset]!;
    const spec = grammar.options.find((candidate) => candidate.short?.includes(spelling));
    if (!spec || (spec.shortPrefixes && !spec.shortPrefixes.includes(sign))) return failure("dynamic-option");
    if (spec.terminal === "deferred") return failure("dynamic-option");
    if (spec.value === "none") {
      options.push(Object.freeze({ id: spec.id, spelling: `${sign}${spelling}`, index, attached: false }));
      continue;
    }
    if (spec.attached !== true) return failure("unsupported-attached-value");
    const option = Object.freeze({ id: spec.id, spelling: `${sign}${spelling}`, index, attached: true, value: word });
    options.push(option);
    return spec.terminal === "immediate"
      ? { kind: "options", options: Object.freeze(options), terminal: option }
      : { kind: "options", options: Object.freeze(options) };
  }
  return failure("dynamic-option");
}

function resolveLong(argument: string, grammar: OptionGrammar):
  | { readonly kind: "resolved"; readonly spec: OptionSpec; readonly spelling: string; readonly attachedValue?: string }
  | { readonly kind: "failure"; readonly reason: OptionScanFailureReason } {
  const resolved = resolveLongOption(
    argument,
    grammar.options.flatMap((spec) => spec.long ?? []),
    grammar.longResolution,
  );
  if (!resolved) return failure("unknown-option");
  if (resolved.kind === "ambiguous") return failure("ambiguous-long-option");
  const spelling = resolved.option;
  const attachedValue = resolved.value;
  const spec = grammar.options.find((candidate) => candidate.long?.includes(spelling))!;
  if (attachedValue !== undefined && spec.value === "none") return failure("unexpected-option-value");
  if (attachedValue !== undefined && spec.equals !== true) return failure("unsupported-attached-value");
  return { kind: "resolved", spec, spelling, ...(attachedValue === undefined ? {} : { attachedValue }) };
}

function consumeOptionValue(
  spec: OptionSpec,
  spelling: string,
  attachedValue: string | undefined,
  arguments_: readonly ResolvedWord[],
  index: number,
):
  | { readonly kind: "consumed"; readonly option: ScannedOption; readonly consumed: number }
  | { readonly kind: "failure"; readonly reason: OptionScanFailureReason } {
  if (spec.value === "none") {
    if (attachedValue !== undefined) return failure("unexpected-option-value");
    return { kind: "consumed", option: Object.freeze({ id: spec.id, spelling, index, attached: false }), consumed: 1 };
  }
  if (attachedValue !== undefined) {
    if (spec.attached !== true && spec.equals !== true) return failure("unsupported-attached-value");
    const value = Object.freeze({ kind: "known" as const, value: attachedValue });
    return { kind: "consumed", option: Object.freeze({ id: spec.id, spelling, index, attached: true, value }), consumed: 1 };
  }
  if (spec.separate === false) return failure("unsupported-separate-value");
  const value = arguments_[index + 1];
  if (!value) return failure("missing-option-value");
  return { kind: "consumed", option: Object.freeze({ id: spec.id, spelling, index, attached: false, value }), consumed: 2 };
}

function parsed(options: readonly ScannedOption[], operandIndex: number, terminal?: ScannedOption): OptionScanResult {
  return Object.freeze({
    kind: "parsed",
    options: Object.freeze([...options]),
    operandIndex,
    ...(terminal ? { terminal } : {}),
  });
}

function failure(reason: OptionScanFailureReason): Extract<OptionScanResult, { readonly kind: "failure" }> {
  return Object.freeze({ kind: "failure", reason });
}
