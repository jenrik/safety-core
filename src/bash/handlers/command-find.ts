import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, policyDeny, strongestOutcome, type Outcome } from "../outcome.js";
import { basename } from "../../shell.js";
import { isSecretPath } from "../../secrets.js";
import type { BashDispatchContinuation } from "../walker.js";
import { continueFrom, wrapperHandler } from "./wrapper-utils.js";

export const findHandler = wrapperHandler("find", parseFind);

function parseFind(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  const continuations: BashDispatchContinuation[] = [];
  const outcomes: Outcome[] = [];
  let foundAction = false;
  for (let index = 0; index < arguments_.length; index++) {
    const current = arguments_[index]!;
    if (current.kind !== "known") {
      outcomes.push(indeterminate(context.span));
      continue;
    }
    const argument = current.value;
    if (argument === "-files0-from") {
      const input = arguments_[index + 1];
      if (!input || input.kind !== "known") return indeterminate(context.span);
      if (isSecretPath(input.value)) {
        return policyDeny(context.span, Object.freeze({
          name: "secret-read",
          decision: "deny" as const,
          reason: `bash \`find\` on '${basename(input.value)}'`,
        }));
      }
      index++;
      continue;
    }
    if (argument !== "-exec" && argument !== "-execdir") continue;

    foundAction = true;
    const end = findTerminator(arguments_, index + 1);
    if (end === undefined) return indeterminate(context.span);
    const child = arguments_.slice(index + 1, end);
    if (child.length === 0 || child.some((word) => word.kind !== "known")) {
      outcomes.push(indeterminate(context.span));
      index = end;
      continue;
    }
    const hasPlaceholder = child.some((word) => word.kind === "known" && word.value === "{}");
    const template = child.map((word) => word.kind === "known" && word.value === "{}"
      ? Object.freeze({ kind: "known" as const, value: "safety-core-dynamic-argument" })
      : word);
    if (hasPlaceholder) outcomes.push(indeterminate(context.span));
    const result = continueFrom(template, 0, context);
    if ("kind" in result) outcomes.push(result);
    else {
      outcomes.push(result.outcome);
      if (result.continuations) continuations.push(...result.continuations);
    }
    index = end;
  }
  if (!foundAction) return indeterminate(context.span);
  const outcome = strongestOutcome(outcomes);
  return continuations.length === 0 ? outcome : { outcome, continuations: Object.freeze(continuations) };
}

function findTerminator(arguments_: readonly ResolvedWord[], start: number): number | undefined {
  for (let index = start; index < arguments_.length; index++) {
    const argument = arguments_[index]!;
    if (argument.kind === "known" && (argument.value === ";" || argument.value === "+")) return index;
  }
  return undefined;
}
