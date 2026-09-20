import type { StructuralDispatchContext } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { dynamicExecutableIndeterminate, strongestOutcome } from "../outcome.js";
import type { BashDispatchResult } from "../walker.js";
import { continueFrom, isKnown, known, resolveLongOption, wrapperHandler } from "./wrapper-utils.js";

const TIME_VALUE_OPTIONS = new Set(["-f", "--format", "-o", "--output"]);
const TIME_FLAGS = new Set(["-a", "--append", "-p", "--portability", "-v", "--verbose", "--quiet", "-V", "--version", "--help"]);
const TIME_LONG_OPTIONS = [...TIME_VALUE_OPTIONS, ...TIME_FLAGS].filter((option) => option.startsWith("--"));
const WATCH_VALUE_OPTIONS = new Set(["-n", "--interval", "-q", "--equexit", "-s", "--shotsdir"]);
const WATCH_FLAGS = new Set([
  "-b", "--beep", "-c", "--color", "-C", "--no-color", "-d", "--differences", "-e", "--errexit",
  "-f", "--follow", "-g", "--chgexit",
  "-p", "--precise", "-r", "--no-rerun", "-t", "--no-title", "-w", "--no-wrap", "-x", "--exec",
  "-h", "--help", "-v", "--version",
]);
const WATCH_LONG_OPTIONS = [...WATCH_VALUE_OPTIONS, ...WATCH_FLAGS].filter((option) => option.startsWith("--"));

export const timeHandler = wrapperHandler("time", parseTime);
export const coprocHandler = wrapperHandler("coproc", parseCoproc);
export const watchHandler = wrapperHandler("watch", parseWatch);

function parseTime(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return dynamic(context);
    if (argument === "--") return dynamic(context, continueExecutorChild(arguments_, index + 1, context));
    const long = resolveLongOption(argument, TIME_LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return dynamic(context);
      if (TIME_VALUE_OPTIONS.has(long.option)) {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return dynamic(context);
        index += long.value === undefined ? 2 : 1;
      } else {
        if (long.value !== undefined) return dynamic(context);
        index++;
      }
      continue;
    }
    if (TIME_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return dynamic(context);
      index += 2;
      continue;
    }
    if (TIME_FLAGS.has(argument)
      || argument.startsWith("--format=")
      || argument.startsWith("--output=")) {
      index++;
      continue;
    }
    const short = parseTimeShortOptions(argument, arguments_[index + 1]);
    if (short) {
      index += short;
      continue;
    }
    if (argument.startsWith("-")) return dynamic(context);
    return dynamic(context, continueExecutorChild(arguments_, index, context));
  }
  return dynamic(context);
}

function parseWatch(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext): BashDispatchResult {
  let index = 0;
  let direct = false;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return dynamic(context);
    if (argument === "--") return watchChild(arguments_, index + 1, direct, context);
    const long = resolveLongOption(argument, WATCH_LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return dynamic(context);
      if (WATCH_VALUE_OPTIONS.has(long.option)) {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return dynamic(context);
        index += long.value === undefined ? 2 : 1;
      } else {
        if (long.value !== undefined && long.option !== "--differences") return dynamic(context);
        if (long.option === "--exec") direct = true;
        index++;
      }
      continue;
    }
    if (WATCH_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return dynamic(context);
      index += 2;
      continue;
    }
    if (WATCH_FLAGS.has(argument)) {
      if (argument === "-x" || argument === "--exec") direct = true;
      index++;
      continue;
    }
    if (["--interval=", "--equexit=", "--shotsdir=", "--differences="].some((option) => argument.startsWith(option))) {
      index++;
      continue;
    }
    const short = parseWatchShortOptions(argument, arguments_[index + 1]);
    if (short) {
      direct ||= short.direct;
      index += short.consumed;
      continue;
    }
    if (argument.startsWith("-")) return dynamic(context);
    return watchChild(arguments_, index, direct, context);
  }
  return dynamic(context);
}

function watchChild(arguments_: readonly ResolvedWord[], index: number, direct: boolean, context: StructuralDispatchContext): BashDispatchResult {
  const child = arguments_.slice(index);
  if (child.length === 0 || child.some((argument) => argument.kind !== "known")) return dynamic(context);
  const result = direct
    ? continueFrom(arguments_, index, context)
    : context.continueWith(child.map((argument) => argument.kind === "known" ? argument.value : "").join(" "), undefined, {
      route: "shell-command",
      sourceDerivedFromBinding: child.some(isBindingResolvedWord),
    });
  return dynamic(context, result);
}

function parseCoproc(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext): BashDispatchResult {
  if (arguments_.length === 0 || arguments_.some((argument, index) => argument.kind !== "known" && !isCoprocGroupMarker(argument, index))) return dynamic(context);
  const first = arguments_[0]!;
  const second = arguments_[1];
  const named = first.kind === "known" && /^[A-Z_][A-Z0-9_]*$/.test(first.value) && arguments_.length > 1;
  const start = isCoprocGroupMarker(second, 1)
    ? 2
    : isCoprocGroupMarker(first, 0)
      ? 1
      : named ? 1 : 0;
  return dynamic(context, continueExecutorChild(arguments_, start, context));
}

function isCoprocGroupMarker(argument: ResolvedWord | undefined, index: number): boolean {
  return argument?.kind === "unknown" && argument.reason.kind === "brace-expansion" && index <= 1;
}

function dynamic(context: StructuralDispatchContext, result?: BashDispatchResult): BashDispatchResult {
  const uncertain = dynamicExecutableIndeterminate(context.span);
  if (!result) return uncertain;
  if ("kind" in result) return strongestOutcome([result, uncertain]);
  return Object.freeze({ ...result, outcome: strongestOutcome([result.outcome, uncertain]) });
}

function continueExecutorChild(arguments_: readonly ResolvedWord[], index: number, context: StructuralDispatchContext): BashDispatchResult {
  const child = arguments_.slice(index);
  if (child.length === 0 || child.some((argument) => argument.kind !== "known")) return dynamicExecutableIndeterminate(context.span);
  let executableSeen = false;
  const source = child.map((argument) => {
    if (argument.kind !== "known") return "";
    const assignment = !executableSeen && /^([A-Za-z_][A-Za-z0-9_]*)(\+?=)(.*)$/s.exec(argument.value);
    if (assignment) return `${assignment[1]}${assignment[2]}${quote(assignment[3]!)}`;
    executableSeen = true;
    return quote(argument.value);
  }).join(" ");
  return context.continueWith(source, undefined, {
    route: "transparent-wrapper",
    sourceDerivedFromBinding: child.some(isBindingResolvedWord),
  });
}

function parseTimeShortOptions(argument: string, next: ResolvedWord | undefined): 1 | 2 | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if ("apqvV".includes(option)) continue;
    if (option !== "f" && option !== "o") return undefined;
    return options.slice(index + 1).length > 0 ? 1 : isKnown(next) ? 2 : undefined;
  }
  return 1;
}

function parseWatchShortOptions(argument: string, next: ResolvedWord | undefined): { readonly consumed: 1 | 2; readonly direct: boolean } | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  let direct = false;
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (option === "d") {
      if (index + 1 < options.length) return { consumed: 1, direct };
      continue;
    }
    if (option === "x") direct = true;
    if ("bcCefghprtvwx".includes(option)) continue;
    if (!"nqs".includes(option)) return undefined;
    const attached = options.slice(index + 1);
    return attached.length > 0
      ? { consumed: 1, direct }
      : isKnown(next) ? { consumed: 2, direct } : undefined;
  }
  return { consumed: 1, direct };
}

function quote(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
