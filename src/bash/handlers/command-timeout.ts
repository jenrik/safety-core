import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

export const timeoutHandler = wrapperHandler("timeout", parseTimeout);

function parseTimeout(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return durationThenChild(arguments_, index + 1, context);
    if (argument === "-k" || argument === "--kill-after" || argument === "-s" || argument === "--signal") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    const short = parseShortOptions(argument, arguments_[index + 1]);
    if (short) { index += short; continue; }
    if (argument.startsWith("--kill-after=") || argument.startsWith("--signal=")
      || ["-f", "--foreground", "-p", "--preserve-status", "-v", "--verbose"].includes(argument)) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index + 1, context);
  }
  return indeterminate(context.span);
}

function parseShortOptions(argument: string, next: ResolvedWord | undefined): 1 | 2 | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (["f", "p", "v"].includes(option)) continue;
    if (option !== "k" && option !== "s") return undefined;
    return options.slice(index + 1).length > 0 ? 1 : isKnown(next) ? 2 : undefined;
  }
  return 1;
}

function durationThenChild(arguments_: readonly ResolvedWord[], index: number, context: StructuralDispatchContext) {
  if (!isKnown(arguments_[index])) return indeterminate(context.span);
  return continueFrom(arguments_, index + 1, context);
}
