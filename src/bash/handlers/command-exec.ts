import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

export const execHandler = wrapperHandler("exec", parseExec);

function parseExec(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  let changesInvocation = false;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") {
      const result = continueFrom(arguments_, index + 1, context);
      return changesInvocation ? taintWrapperResult(result, context) : result;
    }
    if (argument === "-a") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      changesInvocation = true;
      index += 2;
      continue;
    }
    if (argument === "-c" || argument === "-l") {
      changesInvocation = true;
      index++;
      continue;
    }
    if (/^-[cla]+$/.test(argument)) {
      changesInvocation = true;
      if (argument.includes("a")) {
        if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
        index += 2;
      } else index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    const result = continueFrom(arguments_, index, context);
    return changesInvocation ? taintWrapperResult(result, context) : result;
  }
  return indeterminate(context.span);
}
