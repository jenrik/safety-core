import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { childInvocationFrom, isKnown, known, resolveLongOption, wrapperHandler } from "./wrapper-utils.js";

const LONG_OPTIONS = ["--adjustment", "--help", "--version"];

export const niceHandler = wrapperHandler("nice", parseNice);

function parseNice(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return childInvocationFrom(arguments_, index + 1, context, undefined, "exec-replace");
    const long = resolveLongOption(argument, LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return indeterminate(context.span);
      if (long.option === "--adjustment") {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return indeterminate(context.span);
        index += long.value === undefined ? 2 : 1;
      } else {
        if (long.value !== undefined) return indeterminate(context.span);
        index++;
      }
      continue;
    }
    if (/^-\d+$/.test(argument) || /^-n.+/.test(argument) || argument.startsWith("--adjustment=")) { index++; continue; }
    if (argument === "-n" || argument === "--adjustment") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return childInvocationFrom(arguments_, index, context, undefined, "exec-replace");
  }
  return indeterminate(context.span);
}
