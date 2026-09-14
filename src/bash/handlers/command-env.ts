import type { DispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { assignBinding, fromInitialEnvironment, known as knownBinding, setExported, unsetBinding } from "../environment.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, wrapperHandler } from "./wrapper-utils.js";

export const envHandler = wrapperHandler("env", parseEnv);

function parseEnv(arguments_: readonly ResolvedWord[], context: DispatchContext) {
  let index = 0;
  let environment = context.environment;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context, environment);
    if (argument === "-i" || argument === "--ignore-environment") {
      environment = fromInitialEnvironment({}, environment.budgets, "unset");
      index++;
      continue;
    }
    if (argument === "-u" || argument === "--unset") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      environment = unsetBinding(environment, arguments_[index + 1]!.value);
      index += 2;
      continue;
    }
    if (argument === "-C" || argument === "--chdir") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument.startsWith("--unset=")) {
      environment = unsetBinding(environment, argument.slice("--unset=".length));
      index++;
      continue;
    }
    if (argument.startsWith("--chdir=")) {
      index++;
      continue;
    }
    const assigned = assignment(argument);
    if (assigned) {
      environment = setExported(assignBinding(environment, assigned.name, knownBinding(assigned.value)), assigned.name, true);
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context, environment);
  }
  return indeterminate(context.span);
}

function assignment(value: string): { readonly name: string; readonly value: string } | undefined {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(value);
  return match ? { name: match[1]!, value: match[2]! } : undefined;
}
