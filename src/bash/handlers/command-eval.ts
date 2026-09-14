import type { CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";

export const evalHandler: CommandHandler = Object.freeze({
  name: "eval",
  handle(cursor, context) {
    const args = cursor.invocation.argv;
    return args.every((argument) => argument.kind === "known")
      ? context.continueWith(args.map((argument) => argument.value).join(" "), undefined, {
        isolate: false,
        sourceDerivedFromBinding: args.some(isBindingResolvedWord),
      })
      : indeterminate(context.span);
  },
});
