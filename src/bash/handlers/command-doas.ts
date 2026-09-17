import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, safe } from "../outcome.js";
import { continueFrom, isKnown, known, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

export const doasHandler = wrapperHandler("doas", parseDoas);

function parseDoas(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return taintWrapperResult(continueFrom(arguments_, index + 1, context), context);
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
    if (/^-[nsuC]+$/.test(argument) && argument.length > 2) {
      const options = argument.slice(1);
      for (let offset = 0; offset < options.length; offset++) {
        const option = options[offset]!;
        if (option === "n") continue;
        if (option === "s") return indeterminate(context.span);
        if (option !== "u" && option !== "C") return indeterminate(context.span);
        const attached = options.slice(offset + 1);
        const hasSeparate = attached.length === 0;
        if (hasSeparate && !isKnown(arguments_[index + 1])) return indeterminate(context.span);
        if (option === "C") return safe();
        index += hasSeparate ? 2 : 1;
        break;
      }
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return taintWrapperResult(continueFrom(arguments_, index, context), context);
  }
  return indeterminate(context.span);
}
