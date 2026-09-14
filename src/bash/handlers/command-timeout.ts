import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

export const timeoutHandler = wrapperHandler("timeout", parseTimeout);

function parseTimeout(arguments_: readonly ResolvedWord[], context: DispatchContext) {
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
    if (argument.startsWith("--kill-after=") || argument.startsWith("--signal=") || argument === "--foreground" || argument === "--preserve-status") {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index + 1, context);
  }
  return indeterminate(context.span);
}

function durationThenChild(arguments_: readonly ResolvedWord[], index: number, context: DispatchContext) {
  if (!isKnown(arguments_[index])) return indeterminate(context.span);
  return continueFrom(arguments_, index + 1, context);
}
