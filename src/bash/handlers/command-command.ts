import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, safe } from "../outcome.js";
import { childInvocationFrom, known, wrapperHandler } from "./wrapper-utils.js";

export const commandHandler = wrapperHandler("command", parseCommand);

function parseCommand(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return childInvocationFrom(arguments_, index + 1, context, undefined, "none");
    if (argument === "-p") {
      index++;
      continue;
    }
    if (argument === "-v" || argument === "-V") return safe();
    if (argument.startsWith("-")) return indeterminate(context.span);
    return childInvocationFrom(arguments_, index, context, undefined, "none");
  }
  return indeterminate(context.span);
}
