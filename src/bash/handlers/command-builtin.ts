import type { CommandHandler } from "../dispatch.js";
import { policyIndeterminate } from "../outcome.js";
import { evalArguments } from "./command-eval.js";
import { continueFrom, taintWrapperResult } from "./wrapper-utils.js";

const EXECUTABLE_TARGETS = new Set(["command", "exec", "source", "."]);

/** Preserve child evidence for builtins that dispatch code or another command. */
export const builtinHandler: CommandHandler = Object.freeze({
  name: "builtin",
  handle(cursor, context) {
    const args = cursor.invocation.argv;
    const targetIndex = args[0]?.kind === "known" && args[0].value === "--" ? 1 : 0;
    const target = args[targetIndex];
    if (target?.kind === "known" && target.value === "eval") {
      return taintWrapperResult(evalArguments(args.slice(targetIndex + 1), context), context);
    }
    if (target?.kind === "known" && EXECUTABLE_TARGETS.has(target.value)) {
      return taintWrapperResult(continueFrom(args, targetIndex, context), context);
    }
    return policyIndeterminate(context.span, {
      name: "generic-read-only",
      decision: "defer",
      readOnly: { tool: "dynamic-executable" },
    });
  },
});
