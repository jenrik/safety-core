import type { CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { hasUnsafeWrapperEnvelope, taintWrapperResult } from "./wrapper-utils.js";

export const evalHandler: CommandHandler = Object.freeze({
  name: "eval",
  handle(cursor, context) {
    const result = evalArguments(cursor.invocation.argv, context);
    return hasUnsafeWrapperEnvelope(cursor) ? taintWrapperResult(result, context) : result;
  },
});

export function evalArguments(
  invocationArguments: readonly ResolvedWord[],
  context: Parameters<CommandHandler["handle"]>[1],
) {
  const args = invocationArguments[0]?.kind === "known" && invocationArguments[0].value === "--"
    ? invocationArguments.slice(1)
    : invocationArguments;
  return args.every((argument) => argument.kind === "known")
    ? context.continueWith(args.map((argument) => argument.value).join(" "), undefined, {
      isolate: false,
      route: "eval",
      sourceDerivedFromBinding: args.some(isBindingResolvedWord),
    })
    : indeterminate(context.span);
}
