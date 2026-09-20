import type { CommandHandler, StructuralDispatchContext, InvocationCursor } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, strongestOutcome, type Outcome } from "../outcome.js";
import type { BashDispatchResult } from "../walker.js";
import type { ProcessEffect } from "../walker.js";
import { resolveLongOption as resolveDeclaredLongOption } from "../options.js";

export type WrapperParser = (arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) => BashDispatchResult;

export function wrapperHandler(name: string, parse: WrapperParser): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor: InvocationCursor, context: StructuralDispatchContext): BashDispatchResult {
      const parsed = parse(cursor.invocation.argv, context);
      const result = "kind" in parsed && (parsed.kind === "indeterminate" || parsed.kind === "failure")
        ? opaqueWrapperResult(parsed, context)
        : parsed;
      return hasUnsafeWrapperEnvelope(cursor)
        ? taintWrapperResult(result, context)
        : result;
    },
  });
}

/** A recognized wrapper grammar failure still represents a possible child execution. */
export function opaqueWrapperResult(outcome: Outcome, context: StructuralDispatchContext): BashDispatchResult {
  const opaque = context.continueWithOpaque("structural-parse-failure");
  return "kind" in opaque
    ? strongestOutcome([outcome, opaque])
    : Object.freeze({ ...opaque, outcome: strongestOutcome([outcome, opaque.outcome]) });
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
  processEffect: ProcessEffect = "exec-replace",
): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return childInvocationFrom(arguments_, index + 1, context, undefined, processEffect);
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
    return childInvocationFrom(arguments_, index, context, undefined, processEffect);
  }
  return indeterminate(context.span);
}

export function childInvocationFrom(
  arguments_: readonly ResolvedWord[],
  index: number,
  context: StructuralDispatchContext,
  environment: StructuralDispatchContext["environment"] | undefined,
  processEffect: ProcessEffect,
): BashDispatchResult {
  const child = arguments_.slice(index);
  if (child.length === 0 || child[0]?.kind !== "known") return indeterminate(context.span);
  return context.continueWithInvocation(child, environment, {
    route: "transparent-wrapper",
    processEffect,
    isolate: processEffect !== "none",
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
  return resolveDeclaredLongOption(argument, options, "unique-prefix");
}
