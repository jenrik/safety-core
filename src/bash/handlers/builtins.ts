import type { NormalizedCommand, ResolvedWord } from "../expand.js";
import {
  assignBinding,
  assignLocalBinding,
  known,
  lookupBinding,
  setExported,
  setReadonly,
  taintFrame,
  unknown,
  unset,
  unsetBinding,
  type Environment,
} from "../environment.js";
import { indeterminate, type Outcome } from "../outcome.js";

export interface BuiltinTransition {
  readonly handled: boolean;
  readonly environment: Environment;
  readonly writes: readonly string[];
  readonly outcome?: Outcome;
  readonly returned: boolean;
  /** Lets the injected Task 6 router inspect transparent shell builtins. */
  readonly dispatch?: boolean;
}

/**
 * Applies the small set of shell builtins whose state transitions are part of
 * the supported Bash subset. This never executes a process or reads ambient
 * state; unmodelled builtins remain the dispatcher's responsibility.
 */
export function transitionBuiltin(
  command: NormalizedCommand,
  environment: Environment,
  span: { readonly start: number; readonly end: number },
): BuiltinTransition {
  if (command.executable?.kind !== "known") return unhandled(environment);

  switch (command.executable.value) {
    case "local":
      return assignDeclaration(command, environment, true, false, false);
    case "export":
      return assignDeclaration(command, environment, false, true, false);
    case "readonly":
      return assignDeclaration(command, environment, false, false, true);
    case "unset":
      return unsetNames(command, environment);
    case "read":
      return readName(command, environment, span);
    case "return":
      return freeze({ handled: true, environment, writes: freezeArray([]), returned: true });
    case "eval":
    case "source":
    case ".":
      return freeze({
        handled: true,
        environment: taintFrame(environment, { kind: `unsupported-${command.executable.value}` }),
        writes: freezeArray([]),
        outcome: indeterminate(span),
        returned: false,
        dispatch: true,
      });
    default:
      return unhandled(environment);
  }
}

function assignDeclaration(
  command: NormalizedCommand,
  initial: Environment,
  local: boolean,
  exported: boolean,
  readonly: boolean,
): BuiltinTransition {
  let environment = initial;
  const writes: string[] = [];

  for (const argument of command.argv) {
    if (argument.kind !== "known") continue;
    const assignment = splitAssignment(argument.value);
    const name = assignment?.name ?? argument.value;
    if (!isName(name)) continue;

    if (local && !assignment) {
      environment = assignLocalBinding(environment, name, unset());
      writes.push(name);
    } else if (assignment && !lookupBinding(environment, name).readonly) {
      environment = local
        ? assignLocalBinding(environment, name, known(assignment.value))
        : assignBinding(environment, name, known(assignment.value));
      writes.push(name);
    }
    if (exported) {
      environment = setExported(environment, name, true);
      if (!writes.includes(name)) writes.push(name);
    }
    if (readonly) {
      environment = setReadonly(environment, name, true);
      if (!writes.includes(name)) writes.push(name);
    }
  }

  return freeze({ handled: true, environment, writes: freezeArray(writes), returned: false });
}

function unsetNames(command: NormalizedCommand, initial: Environment): BuiltinTransition {
  let environment = initial;
  const writes: string[] = [];
  for (const argument of command.argv) {
    if (argument.kind !== "known" || !isName(argument.value)) continue;
    if (!lookupBinding(environment, argument.value).readonly) {
      environment = unsetBinding(environment, argument.value);
      writes.push(argument.value);
    }
  }
  return freeze({ handled: true, environment, writes: freezeArray(writes), returned: false });
}

function readName(
  command: NormalizedCommand,
  initial: Environment,
  span: { readonly start: number; readonly end: number },
): BuiltinTransition {
  const name = command.argv.length === 1 ? command.argv[0] : undefined;
  if (!name || name.kind !== "known" || !isName(name.value)) return freeze({
    handled: true,
    environment: taintFrame(initial, { kind: "unsupported-read-target" }),
    writes: freezeArray([]),
    outcome: indeterminate(span),
    returned: false,
  });
  return freeze({
    handled: true,
    environment: assignBinding(initial, name.value, unknown({ kind: "read" })),
    writes: freezeArray([name.value]),
    returned: false,
  });
}

function splitAssignment(value: string): { readonly name: string; readonly value: string } | undefined {
  const index = value.indexOf("=");
  if (index <= 0) return undefined;
  const name = value.slice(0, index);
  return isName(name) ? { name, value: value.slice(index + 1) } : undefined;
}

function isName(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(value);
}

function unhandled(environment: Environment): BuiltinTransition {
  return freeze({ handled: false, environment, writes: freezeArray([]), returned: false });
}

function freezeArray<T>(values: readonly T[]): readonly T[] {
  return Object.freeze([...values]);
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
