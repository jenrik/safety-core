import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

const VALUE_OPTIONS = new Set(["-e", "-o", "-p", "-P", "-s", "-u", "-E", "-a"]);
const FLAGS = new Set(["-f", "-ff", "-c", "-C", "-D", "-dd", "-ddd", "-h", "-q", "-qq", "-r", "-t", "-tt", "-ttt", "-T", "-v", "-V", "-x", "-xx"]);

export const straceHandler = wrapperHandler("strace", parseStrace);

function parseStrace(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (FLAGS.has(argument) || /^-(?:e|o|p|P|s|u|E|a).+/.test(argument)) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}
