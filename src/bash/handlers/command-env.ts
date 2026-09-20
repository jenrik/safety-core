import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { assignBinding, fromInitialEnvironment, known as knownBinding, setExported, unsetBinding } from "../environment.js";
import { indeterminate } from "../outcome.js";
import { childInvocationFrom, isKnown, known, resolveLongOption, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

const ENV_VALUE_OPTIONS = new Set(["--unset", "--chdir", "--argv0", "--split-string"]);
const ENV_FLAGS = new Set(["--ignore-environment", "--null", "--debug", "--list-signal-handling", "--help", "--version"]);
const ENV_OPTIONAL_VALUE_OPTIONS = new Set(["--block-signal", "--default-signal", "--ignore-signal"]);
const ENV_LONG_OPTIONS = [...ENV_VALUE_OPTIONS, ...ENV_FLAGS, ...ENV_OPTIONAL_VALUE_OPTIONS];

export const envHandler = wrapperHandler("env", parseEnv);

function parseEnv(initialArguments: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let arguments_ = [...initialArguments];
  let index = 0;
  let environment = context.environment;
  let unsafe = false;
  let splitCount = 0;
  argumentLoop: while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") {
      const result = childInvocationFrom(arguments_, index + 1, context, environment, "exec-replace");
      return unsafe ? taintWrapperResult(result, context) : result;
    }
    const long = resolveLongOption(argument, ENV_LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return indeterminate(context.span);
      const option = long.option;
      if (option === "--ignore-environment") {
        if (long.value !== undefined) return indeterminate(context.span);
        environment = fromInitialEnvironment({}, environment.budgets, "unset");
        unsafe = true;
        index++;
        continue;
      }
      if (ENV_VALUE_OPTIONS.has(option)) {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return indeterminate(context.span);
        const value = long.value ?? arguments_[index + 1]!.value;
        unsafe = true;
        if (option === "--unset") environment = unsetBinding(environment, value);
        if (option === "--split-string") {
          if (++splitCount > 8) return indeterminate(context.span);
          const split = splitEnvString(value);
          if (!split || arguments_.length + split.length > 256) return indeterminate(context.span);
          arguments_ = [
            ...arguments_.slice(0, index),
            ...split.map(resolved),
            ...arguments_.slice(index + (long.value === undefined ? 2 : 1)),
          ];
          continue;
        }
        index += long.value === undefined ? 2 : 1;
        continue;
      }
      if (ENV_FLAGS.has(option) && long.value !== undefined) return indeterminate(context.span);
      if (ENV_OPTIONAL_VALUE_OPTIONS.has(option)) unsafe = true;
      index++;
      continue;
    }
    if (argument === "-" || argument === "-i" || argument === "--ignore-environment") {
      environment = fromInitialEnvironment({}, environment.budgets, "unset");
      unsafe = true;
      index++;
      continue;
    }
    if (argument === "-u" || argument === "--unset") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      environment = unsetBinding(environment, arguments_[index + 1]!.value);
      unsafe = true;
      index += 2;
      continue;
    }
    if (argument === "-C" || argument === "--chdir") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      unsafe = true;
      index += 2;
      continue;
    }
    if (argument === "-a" || argument === "--argv0") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      unsafe = true;
      index += 2;
      continue;
    }
    if (argument === "-S" || argument === "--split-string") {
      const value = arguments_[index + 1];
      if (!isKnown(value) || ++splitCount > 8) return indeterminate(context.span);
      const split = splitEnvString(value.value);
      if (!split || arguments_.length + split.length > 256) return indeterminate(context.span);
      arguments_ = [...arguments_.slice(0, index), ...split.map(resolved), ...arguments_.slice(index + 2)];
      unsafe = true;
      continue;
    }
    if (argument.startsWith("--unset=")) {
      environment = unsetBinding(environment, argument.slice("--unset=".length));
      unsafe = true;
      index++;
      continue;
    }
    if (argument.startsWith("--chdir=")) {
      unsafe = true;
      index++;
      continue;
    }
    if (argument.startsWith("--argv0=")) {
      unsafe = true;
      index++;
      continue;
    }
    if (argument.startsWith("--split-string=")) {
      if (++splitCount > 8) return indeterminate(context.span);
      const value = argument.startsWith("--split-string=") ? argument.slice("--split-string=".length) : argument.slice(2);
      const split = splitEnvString(value);
      if (!split || arguments_.length + split.length > 256) return indeterminate(context.span);
      arguments_ = [...arguments_.slice(0, index), ...split.map(resolved), ...arguments_.slice(index + 1)];
      unsafe = true;
      continue;
    }
    if (["-0", "--null", "-v", "--debug", "--list-signal-handling"].includes(argument)) {
      index++;
      continue;
    }
    if (/^-[^-].+/.test(argument)) {
      for (let offset = 1; offset < argument.length; offset++) {
        const option = argument[offset]!;
        if (option === "i") {
          environment = fromInitialEnvironment({}, environment.budgets, "unset");
          unsafe = true;
          continue;
        }
        if (option === "0" || option === "v") continue;
        if (!["u", "C", "a", "S"].includes(option)) return indeterminate(context.span);
        const attached = argument.slice(offset + 1);
        const separate = attached.length === 0;
        const next = separate ? arguments_[index + 1] : undefined;
        if (separate && !isKnown(next)) return indeterminate(context.span);
        const value = separate ? next!.value : attached;
        unsafe = true;
        if (option === "u") environment = unsetBinding(environment, value);
        if (option === "S") {
          if (++splitCount > 8) return indeterminate(context.span);
          const split = splitEnvString(value);
          if (!split || arguments_.length + split.length > 256) return indeterminate(context.span);
          arguments_ = [
            ...arguments_.slice(0, index),
            ...split.map(resolved),
            ...arguments_.slice(index + (separate ? 2 : 1)),
          ];
          continue argumentLoop;
        }
        index += separate ? 2 : 1;
        continue argumentLoop;
      }
      index++;
      continue;
    }
    if (["--block-signal", "--default-signal", "--ignore-signal"].includes(argument)
      || /^(?:--block-signal|--default-signal|--ignore-signal)=/.test(argument)) {
      unsafe = true;
      index++;
      continue;
    }
    const assigned = assignment(argument);
    if (assigned) {
      environment = setExported(assignBinding(environment, assigned.name, knownBinding(assigned.value)), assigned.name, true);
      unsafe = true;
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    const result = childInvocationFrom(arguments_, index, context, environment, "exec-replace");
    return unsafe ? taintWrapperResult(result, context) : result;
  }
  return indeterminate(context.span);
}

function resolved(value: string): ResolvedWord {
  return Object.freeze({ kind: "known", value });
}

/** Parse the static quoting subset used by normal env -S command strings. */
function splitEnvString(value: string): string[] | undefined {
  const words: string[] = [];
  let word = "";
  let quote: "'" | '"' | undefined;
  let started = false;
  for (let index = 0; index < value.length; index++) {
    const character = value[index]!;
    if (!quote && /\s/.test(character)) {
      if (started) words.push(word);
      word = "";
      started = false;
      continue;
    }
    if (character === "'" || character === '"') {
      if (!quote) { quote = character; started = true; continue; }
      if (quote === character) { quote = undefined; continue; }
    }
    if (character === "\\" && quote !== "'") {
      const escaped = value[++index];
      if (escaped === undefined) return undefined;
      word += escaped === "n" ? "\n" : escaped === "t" ? "\t" : escaped;
      started = true;
      continue;
    }
    if (character === "$" && quote !== "'") return undefined;
    word += character;
    started = true;
  }
  if (quote) return undefined;
  if (started) words.push(word);
  return words;
}

function assignment(value: string): { readonly name: string; readonly value: string } | undefined {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(value);
  return match ? { name: match[1]!, value: match[2]! } : undefined;
}
