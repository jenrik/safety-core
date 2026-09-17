import type { CommandHandler } from "../dispatch.js";
import { indeterminate } from "../outcome.js";
import { evalArguments } from "./command-eval.js";
import { taintWrapperResult } from "./wrapper-utils.js";

/** Unwrap only builtin eval; sourced files remain outside the static-analysis boundary. */
export const builtinHandler: CommandHandler = Object.freeze({
  name: "builtin",
  handle(cursor, context) {
    const args = cursor.invocation.argv;
    const targetIndex = args[0]?.kind === "known" && args[0].value === "--" ? 1 : 0;
    const target = args[targetIndex];
    if (target?.kind !== "known" || target.value !== "eval") return indeterminate(context.span);
    return taintWrapperResult(evalArguments(args.slice(targetIndex + 1), context), context);
  },
});
