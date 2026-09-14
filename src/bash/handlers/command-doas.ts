import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, safe } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

export const doasHandler = wrapperHandler("doas", parseDoas);

function parseDoas(arguments_: readonly ResolvedWord[], context: DispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (argument === "-n") {
      index++;
      continue;
    }
    if (argument === "-u") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument === "-C") {
      return isKnown(arguments_[index + 1]) ? safe() : indeterminate(context.span);
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}
