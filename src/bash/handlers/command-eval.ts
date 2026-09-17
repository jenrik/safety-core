import type { CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { hasUnsafeWrapperEnvelope, taintWrapperResult } from "./wrapper-utils.js";

export const evalHandler: CommandHandler = Object.freeze({
  name: "eval",
  handle(cursor, context) {
    const args = cursor.invocation.argv[0]?.kind === "known" && cursor.invocation.argv[0].value === "--"
      ? cursor.invocation.argv.slice(1)
      : cursor.invocation.argv;
    const result = args.every((argument) => argument.kind === "known")
      ? context.continueWith(args.map((argument) => argument.value).join(" "), undefined, {
        isolate: false,
        route: "eval",
        sourceDerivedFromBinding: args.some(isBindingResolvedWord),
      })
      : indeterminate(context.span);
    return hasUnsafeWrapperEnvelope(cursor) ? taintWrapperResult(result, context) : result;
  },
});
