import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { scanOptions, type OptionGrammar } from "../options.js";
import { childInvocationFrom, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

export const execHandler = wrapperHandler("exec", parseExec);

function parseExec(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  const parsed = scanOptions(arguments_, EXEC_OPTIONS);
  if (parsed.kind === "failure" || parsed.operandIndex >= arguments_.length) return indeterminate(context.span);
  const result = childInvocationFrom(arguments_, parsed.operandIndex, context, undefined, "exec-replace");
  return parsed.options.length > 0 ? taintWrapperResult(result, context) : result;
}

const EXEC_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  options: Object.freeze([
    Object.freeze({ id: "argv0", short: Object.freeze(["a"]), value: "required", attached: true }),
    Object.freeze({ id: "clear-environment", short: Object.freeze(["c"]), value: "none" }),
    Object.freeze({ id: "login", short: Object.freeze(["l"]), value: "none" }),
  ]),
});
