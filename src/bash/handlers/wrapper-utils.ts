import type { CommandHandler, StructuralDispatchContext, InvocationCursor } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { indeterminate, type Outcome } from "../outcome.js";
import type { BashDispatchResult } from "../walker.js";

export type WrapperParser = (arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) => BashDispatchResult;

export function wrapperHandler(name: string, parse: WrapperParser): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor: InvocationCursor, context: StructuralDispatchContext): BashDispatchResult {
      return parse(cursor.invocation.argv, context);
    },
  });
}

export function parseOptionChild(
  arguments_: readonly ResolvedWord[],
  context: StructuralDispatchContext,
  valueOptions: ReadonlyMap<string, number>,
  flags: ReadonlySet<string>,
  equalsOptions: readonly string[] = [],
): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    const arity = valueOptions.get(argument);
    if (arity !== undefined) {
      for (let offset = 1; offset <= arity; offset++) if (!isKnown(arguments_[index + offset])) return indeterminate(context.span);
      index += arity + 1;
      continue;
    }
    if (flags.has(argument) || equalsOptions.some((prefix) => argument.startsWith(prefix))) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}

export function continueFrom(
  arguments_: readonly ResolvedWord[],
  index: number,
  context: StructuralDispatchContext,
  environment?: StructuralDispatchContext["environment"],
): BashDispatchResult {
  const child = arguments_.slice(index);
  if (child.length === 0 || child.some((argument) => argument.kind !== "known")) return indeterminate(context.span);
  return context.continueWith(child.map((argument) => quote(argument.value)).join(" "), environment, {
    route: "transparent-wrapper",
    sourceDerivedFromBinding: child.some(isBindingResolvedWord),
  });
}

export function known(argument: ResolvedWord | undefined, context: StructuralDispatchContext): string | Outcome {
  return argument?.kind === "known" ? argument.value : indeterminate(context.span);
}

export function isKnown(argument: ResolvedWord | undefined): argument is Extract<ResolvedWord, { readonly kind: "known" }> {
  return argument?.kind === "known";
}

function quote(value: string): string {
  return `'${value.replaceAll("'", "'\\\"'\\\"'")}'`;
}
