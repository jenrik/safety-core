import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { childInvocationFrom, isKnown, known, resolveLongOption, wrapperHandler } from "./wrapper-utils.js";

const VALUE_OPTIONS = new Set(["--input", "--output", "--error"]);
const LONG_OPTIONS = [...VALUE_OPTIONS, "--help", "--version"];

export const stdbufHandler = wrapperHandler("stdbuf", parseStdbuf);

function parseStdbuf(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return childInvocationFrom(arguments_, index + 1, context, undefined, "exec-replace");
    const long = resolveLongOption(argument, LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return indeterminate(context.span);
      if (VALUE_OPTIONS.has(long.option)) {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return indeterminate(context.span);
        index += long.value === undefined ? 2 : 1;
      } else {
        if (long.value !== undefined) return indeterminate(context.span);
        index++;
      }
      continue;
    }
    if (["-i", "-o", "-e"].includes(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (/^-[ioe].+/.test(argument)) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return childInvocationFrom(arguments_, index, context, undefined, "exec-replace");
  }
  return indeterminate(context.span);
}
