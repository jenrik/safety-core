import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, policyDeny, strongestOutcome, type Outcome } from "../outcome.js";
import { basename } from "../../shell.js";
import { isSecretPath } from "../../secrets.js";
import type { BashChildExecution } from "../walker.js";
import { childInvocationFrom, wrapperHandler } from "./wrapper-utils.js";

export const findHandler = wrapperHandler("find", parseFind);

const GLOBAL_FLAGS = new Set(["-H", "-L", "-P"]);
const OPERATORS = new Set(["(", ")", "!", "-not", "-a", "-and", "-o", "-or", ","]);
const NULLARY_PRIMARIES = new Set([
  "-daystart", "-delete", "-depth", "-empty", "-false", "-follow", "-ignore_readdir_race",
  "-ls", "-mount", "-noignore_readdir_race", "-nogroup", "-noleaf", "-nouser", "-nowarn",
  "-print", "-print0", "-prune", "-quit", "-readable", "-true", "-warn", "-writable",
  "-executable", "-help", "--help", "-version", "--version", "-xdev",
]);
const UNARY_PRIMARIES = new Set([
  "-amin", "-anewer", "-atime", "-cmin", "-cnewer", "-context", "-ctime", "-fls", "-fprint",
  "-fprint0", "-fstype", "-gid", "-group", "-ilname", "-iname", "-inum", "-ipath", "-iregex",
  "-iwholename", "-links", "-lname", "-maxdepth", "-mindepth", "-mmin", "-mtime", "-name",
  "-newer", "-path", "-perm", "-printf", "-regextype", "-samefile", "-size", "-type", "-uid",
  "-used", "-user", "-wholename", "-xtype",
]);
const VARIABLE_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"]);

function parseFind(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  const children: BashChildExecution[] = [];
  const outcomes: Outcome[] = [];
  let executionPossible = false;
  const pending = [{ index: 0, expression: false }];
  const visited = new Set<string>();
  const handledActions = new Set<number>();

  while (pending.length > 0) {
    const state = pending.pop()!;
    const stateKey = `${state.index}:${state.expression}`;
    if (visited.has(stateKey)) continue;
    visited.add(stateKey);
    let { index, expression } = state;

    while (index < arguments_.length) {
      const current = arguments_[index]!;
      if (!expression) {
        if (current.kind !== "known") {
          executionPossible = true;
          outcomes.push(indeterminate(context.span));
          appendOpaque(context, outcomes, children);
          index++;
          continue;
        }
        if (GLOBAL_FLAGS.has(current.value)) {
          index++;
          continue;
        }
        if (current.value === "-D") {
          if (index + 1 >= arguments_.length) return indeterminate(context.span);
          index += 2;
          continue;
        }
        if (current.value.startsWith("-O") && current.value.length > 2) {
          index++;
          continue;
        }
        if (!isExpressionStart(current.value)) {
          index++;
          continue;
        }
        expression = true;
      }

      const argument = arguments_[index]!;
      if (argument.kind !== "known") {
        executionPossible = true;
        outcomes.push(indeterminate(context.span));
        appendOpaque(context, outcomes, children);
        index++;
        continue;
      }

      if (VARIABLE_ACTIONS.has(argument.value)) {
        executionPossible = true;
        const action = findActionEnd(arguments_, index + 1, argument.value === "-exec" || argument.value === "-execdir");
        const possibleBodyEnd = action?.end ?? arguments_.length;
        for (let bodyIndex = index + 1; bodyIndex < possibleBodyEnd; bodyIndex++) {
          if (arguments_[bodyIndex]!.kind !== "known") pending.push({ index: bodyIndex + 1, expression: true });
        }
        if (!handledActions.has(index)) {
          handledActions.add(index);
          if (!action) {
            outcomes.push(indeterminate(context.span));
            appendOpaque(context, outcomes, children);
            break;
          }
          const command = arguments_.slice(index + 1, action.end);
          if (command.length === 0 || command.some((word) => word.kind !== "known")) {
            outcomes.push(indeterminate(context.span));
            appendOpaque(context, outcomes, children);
          } else {
            const hasPlaceholder = command.some((word) => word.kind === "known" && word.value.includes("{}"));
            const template = command.map((word) => word.kind === "known" && word.value.includes("{}")
              ? Object.freeze({ kind: "known" as const, value: word.value.replaceAll("{}", "safety-core-dynamic-argument") })
              : word);
            if (hasPlaceholder) outcomes.push(indeterminate(context.span));
            appendResult(childInvocationFrom(template, 0, context, undefined, "spawn-repeated"), outcomes, children);
          }
        }
        if (!action) break;
        index = action.end + 1;
        continue;
      }

      if (argument.value === "-files0-from") {
        const input = arguments_[index + 1];
        if (!input) {
          executionPossible = true;
          outcomes.push(indeterminate(context.span));
          appendOpaque(context, outcomes, children);
          break;
        }
        if (input.kind !== "known") {
          outcomes.push(indeterminate(context.span));
        } else if (isSecretPath(input.value)) {
          return policyDeny(context.span, Object.freeze({
            name: "secret-read",
            decision: "deny" as const,
            reason: `bash \`find\` on '${basename(input.value)}'`,
          }));
        }
        index += 2;
        continue;
      }

      if (argument.value === "-fprintf") {
        index = consumeFixed(arguments_, index, 2, context, outcomes, children);
        if (index < 0) {
          executionPossible = true;
          break;
        }
        continue;
      }
      if (isNewerPrimary(argument.value) || UNARY_PRIMARIES.has(argument.value)) {
        index = consumeFixed(arguments_, index, 1, context, outcomes, children);
        if (index < 0) {
          executionPossible = true;
          break;
        }
        continue;
      }
      if (OPERATORS.has(argument.value) || NULLARY_PRIMARIES.has(argument.value)) {
        index++;
        continue;
      }

      executionPossible = true;
      outcomes.push(indeterminate(context.span));
      appendOpaque(context, outcomes, children);
      index++;
    }
  }

  if (!executionPossible) return indeterminate(context.span);
  return { outcome: strongestOutcome(outcomes), children: Object.freeze(children) };
}

function consumeFixed(
  arguments_: readonly ResolvedWord[],
  index: number,
  arity: number,
  context: StructuralDispatchContext,
  outcomes: Outcome[],
  children: BashChildExecution[],
): number {
  if (index + arity >= arguments_.length) {
    outcomes.push(indeterminate(context.span));
    appendOpaque(context, outcomes, children);
    return -1;
  }
  return index + arity + 1;
}

function isExpressionStart(argument: string): boolean {
  return argument === "(" || argument === ")" || argument === "!" || argument === "," || argument.startsWith("-");
}

function isNewerPrimary(argument: string): boolean {
  return /^-newer[acmB][acmBt]$/.test(argument);
}

function findActionEnd(
  arguments_: readonly ResolvedWord[],
  start: number,
  allowsBatch: boolean,
): { readonly end: number } | undefined {
  for (let index = start; index < arguments_.length; index++) {
    const argument = arguments_[index]!;
    if (argument.kind !== "known") continue;
    if (argument.value === ";") return { end: index };
    if (allowsBatch && argument.value === "+" && index > start) {
      const previous = arguments_[index - 1];
      const placeholders = arguments_.slice(start, index)
        .filter((word) => word.kind === "known" && word.value === "{}");
      if (previous?.kind === "known" && previous.value === "{}" && placeholders.length === 1) return { end: index };
    }
  }
  return undefined;
}

function appendOpaque(
  context: StructuralDispatchContext,
  outcomes: Outcome[],
  children: BashChildExecution[],
): void {
  appendResult(context.continueWithOpaque("unsupported-execution", undefined, {
    route: "transparent-wrapper",
    processEffect: "spawn-repeated",
  }), outcomes, children);
}

function appendResult(
  result: ReturnType<StructuralDispatchContext["continueWithOpaque"]>,
  outcomes: Outcome[],
  children: BashChildExecution[],
): void {
  if ("kind" in result) outcomes.push(result);
  else {
    outcomes.push(result.outcome);
    if (result.children) children.push(...result.children);
  }
}
