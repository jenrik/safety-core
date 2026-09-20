import type { NormalizedCommand, ResolvedWord } from "../expand.js";
import {
  assignBinding,
  assignLocalBinding,
  hasBinding,
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
import { dynamicExecutableIndeterminate, indeterminate, type Outcome } from "../outcome.js";
import { scanOptions, type OptionGrammar } from "../options.js";
import {
  invalidateShellFunction,
  invalidateShellFunctions,
  removeShellFunction,
  taintShellState,
  withShellEnvironment,
  type BashShellState,
} from "../state.js";

export interface BuiltinTransition {
  readonly handled: boolean;
  readonly state: BashShellState;
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
  state: BashShellState,
  span: { readonly start: number; readonly end: number },
): BuiltinTransition {
  if (command.executable?.kind !== "known") return unhandled(state);

  switch (command.executable.value) {
    case "local":
      return withEnvironmentTransition(state, assignDeclaration(command, state.environment, true, false, false));
    case "export":
      return withEnvironmentTransition(state, assignDeclaration(command, state.environment, false, true, false));
    case "readonly":
      return withEnvironmentTransition(state, assignDeclaration(command, state.environment, false, false, true));
    case "unset":
      return unsetNames(command, state, span);
    case "read":
      return withEnvironmentTransition(state, readName(command, state.environment, span));
    case "return":
      return freeze({ handled: true, state, writes: freezeArray([]), returned: true });
    case "eval":
    case "source":
    case ".":
      return freeze({
        handled: true,
        state: withShellEnvironment(state, taintFrame(state.environment, { kind: `unsupported-${command.executable.value}` })),
        writes: freezeArray([]),
        outcome: command.executable.value === "eval" ? indeterminate(span) : dynamicExecutableIndeterminate(span),
        returned: false,
        dispatch: true,
      });
    default:
      return unhandled(state);
  }
}

interface EnvironmentTransition {
  readonly handled: boolean;
  readonly environment: Environment;
  readonly writes: readonly string[];
  readonly outcome?: Outcome;
  readonly returned: boolean;
  readonly dispatch?: boolean;
}

function assignDeclaration(
  command: NormalizedCommand,
  initial: Environment,
  local: boolean,
  exported: boolean,
  readonly: boolean,
): EnvironmentTransition {
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

function unsetNames(
  command: NormalizedCommand,
  initial: BashShellState,
  span: { readonly start: number; readonly end: number },
): BuiltinTransition {
  const parsed = scanOptions(command.argv, UNSET_OPTIONS);
  if (parsed.kind === "failure") {
    const state = parsed.reason === "dynamic-option"
      ? taintShellState(initial, { kind: "dynamic-unset-option", span })
      : initial;
    return freeze({ handled: true, state, writes: freezeArray([]), outcome: indeterminate(span), returned: false });
  }

  const ids = new Set(parsed.options.map((option) => option.id));
  if (ids.has("function") && ids.has("variable")) {
    return freeze({ handled: true, state: initial, writes: freezeArray([]), outcome: indeterminate(span), returned: false });
  }
  if (ids.has("nameref") && !ids.has("function")) {
    return freeze({
      handled: true,
      state: taintShellState(initial, { kind: "unsupported-unset-nameref", span }),
      writes: freezeArray([]),
      outcome: indeterminate(span),
      returned: false,
    });
  }

  let state = initial;
  const writes: string[] = [];
  for (const argument of command.argv.slice(parsed.operandIndex)) {
    if (argument.kind !== "known") {
      if (ids.has("function")) state = invalidateShellFunctions(state);
      else if (ids.has("variable")) {
        state = withShellEnvironment(state, taintFrame(state.environment, { kind: "dynamic-unset-variable", span }));
      } else state = taintShellState(state, { kind: "dynamic-unset-name", span });
      continue;
    }

    const name = argument.value;
    if (!isName(name)) continue;
    if (ids.has("function")) {
      state = removeShellFunction(state, name);
      continue;
    }

    const binding = lookupBinding(state.environment, name);
    if (ids.has("variable")) {
      if (!binding.readonly) {
        state = withShellEnvironment(state, unsetBinding(state.environment, name));
        writes.push(name);
      }
      continue;
    }

    const variableDefinitelyAbsent = binding.value.kind === "unset"
      && (hasBinding(state.environment, name) || state.environment.missingBindings === "unset");
    if (variableDefinitelyAbsent) {
      state = removeShellFunction(state, name);
    } else if (!hasBinding(state.environment, name) && state.environment.missingBindings === "unknown") {
      state = invalidateShellFunction(state, name);
      state = withShellEnvironment(state, unsetBinding(state.environment, name));
      writes.push(name);
    } else if (!binding.readonly) {
      state = withShellEnvironment(state, unsetBinding(state.environment, name));
      writes.push(name);
    }
  }
  return freeze({ handled: true, state, writes: freezeArray(writes), returned: false });
}

function readName(
  command: NormalizedCommand,
  initial: Environment,
  span: { readonly start: number; readonly end: number },
): EnvironmentTransition {
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

function withEnvironmentTransition(initial: BashShellState, transition: EnvironmentTransition): BuiltinTransition {
  const { environment, ...result } = transition;
  return freeze({ ...result, state: withShellEnvironment(initial, environment) });
}

function unhandled(state: BashShellState): BuiltinTransition {
  return freeze({ handled: false, state, writes: freezeArray([]), returned: false });
}

const UNSET_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  options: Object.freeze([
    Object.freeze({ id: "function", short: Object.freeze(["f"]), value: "none" }),
    Object.freeze({ id: "variable", short: Object.freeze(["v"]), value: "none" }),
    Object.freeze({ id: "nameref", short: Object.freeze(["n"]), value: "none" }),
  ]),
});

function freezeArray<T>(values: readonly T[]): readonly T[] {
  return Object.freeze([...values]);
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
