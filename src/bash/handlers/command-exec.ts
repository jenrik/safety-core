import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

export const execHandler = wrapperHandler("exec", parseExec);

function parseExec(arguments_: readonly ResolvedWord[], context: DispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (argument === "-a") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument === "-c" || argument === "-l") {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}
