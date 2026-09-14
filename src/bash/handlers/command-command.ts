import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, safe } from "../outcome.js";
import { continueFrom, known, wrapperHandler } from "./wrapper-utils.js";

export const commandHandler = wrapperHandler("command", parseCommand);

function parseCommand(arguments_: readonly ResolvedWord[], context: DispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (argument === "-p") {
      index++;
      continue;
    }
    if (argument === "-v" || argument === "-V") return safe();
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}
