import type { StructuralDispatchContext } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { dynamicExecutableIndeterminate, strongestOutcome } from "../outcome.js";
import type { BashDispatchResult } from "../walker.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

const TIME_VALUE_OPTIONS = new Set(["-f", "--format", "-o", "--output"]);
const TIME_FLAGS = new Set(["-a", "--append", "-p", "--portability", "-v", "--verbose", "--quiet", "-V", "--version", "--help"]);
const WATCH_VALUE_OPTIONS = new Set(["-n", "--interval", "-q", "--equexit", "-s", "--shotsdir"]);
const WATCH_FLAGS = new Set([
  "-b", "--beep", "-c", "--color", "-d", "--differences", "-e", "--errexit", "-g", "--chgexit",
  "-p", "--precise", "-r", "--no-rerun", "-t", "--no-title", "-w", "--no-wrap", "-x", "--exec",
  "--help", "--version",
]);

export const timeHandler = wrapperHandler("time", parseTime);
export const coprocHandler = wrapperHandler("coproc", parseCoproc);
export const watchHandler = wrapperHandler("watch", parseWatch);

function parseTime(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return dynamic(context);
    if (argument === "--") return dynamic(context, continueFrom(arguments_, index + 1, context));
    if (TIME_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return dynamic(context);
      index += 2;
      continue;
    }
    if (TIME_FLAGS.has(argument)
      || /^-[fo].+/.test(argument)
      || argument.startsWith("--format=")
      || argument.startsWith("--output=")) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return dynamic(context);
    return dynamic(context, continueFrom(arguments_, index, context));
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
    if (/^-[nqs].+/.test(argument)
      || ["--interval=", "--equexit=", "--shotsdir=", "--differences="].some((option) => argument.startsWith(option))) {
      index++;
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
  return dynamic(context, continueFrom(arguments_, start, context));
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
