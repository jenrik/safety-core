import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { wrapperHandler } from "./wrapper-utils.js";

/** xargs supplies runtime stdin items, so even static templates are not closed child invocations. */
export const xargsHandler = wrapperHandler("xargs", (_arguments_: readonly ResolvedWord[], context: DispatchContext) =>
  indeterminate(context.span),
);
