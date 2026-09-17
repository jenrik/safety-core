import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { continueFrom, known, parseOptionChild, wrapperHandler } from "./wrapper-utils.js";

export const setsidHandler = wrapperHandler("setsid", parseSetsid);

function parseSetsid(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (/^-[cfw]+$/.test(argument) || ["--ctty", "--fork", "--wait"].includes(argument)) {
      index++;
      continue;
    }
    break;
  }
  return parseOptionChild(arguments_.slice(index), context, new Map(), new Set());
}
