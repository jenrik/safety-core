import type { CommandHandler, StructuralDispatchContext, InvocationCursor } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { indeterminate, strongestOutcome, type Outcome } from "../outcome.js";
import type { BashDispatchResult } from "../walker.js";

export type WrapperParser = (arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) => BashDispatchResult;

export function wrapperHandler(name: string, parse: WrapperParser): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor: InvocationCursor, context: StructuralDispatchContext): BashDispatchResult {
      const result = parse(cursor.invocation.argv, context);
      return hasUnsafeWrapperEnvelope(cursor)
        ? taintWrapperResult(result, context)
        : result;
    },
  });
}

export function hasUnsafeWrapperEnvelope(cursor: InvocationCursor): boolean {
  const executable = cursor.invocation.executable;
  return (executable?.kind === "known" && executable.value.includes("/"))
    || cursor.invocation.assignmentPatch.writes.size > 0
    || cursor.invocation.redirects.length > 0;
}

/** Preserve child analysis while preventing unsafe wrapper behavior from authorizing it. */
export function taintWrapperResult(result: BashDispatchResult, context: StructuralDispatchContext): BashDispatchResult {
  const uncertain = indeterminate(context.span);
  if ("kind" in result) return strongestOutcome([result, uncertain]);
  return Object.freeze({ ...result, outcome: strongestOutcome([result.outcome, uncertain]) });
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

export function resolveLongOption(argument: string, options: readonly string[]):
  | { readonly kind: "known"; readonly option: string; readonly value?: string }
  | { readonly kind: "ambiguous" }
  | undefined {
  if (!argument.startsWith("--") || argument === "--") return undefined;
  const equals = argument.indexOf("=");
  const name = equals < 0 ? argument : argument.slice(0, equals);
  const exact = options.includes(name) ? name : undefined;
  const matches = exact ? [exact] : options.filter((option) => option.startsWith(name));
  if (matches.length === 0) return undefined;
  if (matches.length > 1) return { kind: "ambiguous" };
  return {
    kind: "known",
    option: matches[0]!,
    ...(equals < 0 ? {} : { value: argument.slice(equals + 1) }),
  };
}

function quote(value: string): string {
  return `'${value.replaceAll("'", "'\\\"'\\\"'")}'`;
}
