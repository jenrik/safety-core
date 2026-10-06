import type { BashFunction } from "./cst.js";
import {
  assignBinding,
  assignNonLocalBinding,
  type BranchCheckpoint,
  type Environment,
  forkCheckpoint,
  hasBinding,
  lookupBinding,
  mergeCheckpoint,
  setExported,
  taintFrame,
  type UnknownReason,
  unknown,
  unsetBinding,
} from "./environment.js";
import { inheritedBashFunctionFact } from "./policy-environment.js";

/** Every abstract shell fact visible to later commands in the current scope. */
export interface BashShellState {
  readonly environment: Environment;
  /** Null when a directory-changing transition cannot be proved. */
  readonly cwd: string | null;
  /**
   * True when a directory change moved the shell somewhere we cannot name, so
   * cwd-dependent external command resolution must fail closed. It is distinct
   * from an unknown initial `cwd`: a snapshot that never observed a directory
   * change carries the environment's own relative-PATH semantics unchanged.
   * `cwd` itself stays null after any directory change so relative file
   * accesses remain unproved; this flag only governs command resolution.
   */
  readonly cwdUncertain: boolean;
  readonly functionCandidates: ReadonlyMap<string, readonly BashFunction[]>;
  /** Names that may still resolve externally on at least one reachable path. */
  readonly missingFunctions: ReadonlySet<string>;
}

export interface BashShellStatePatch {
  readonly state: BashShellState;
  readonly writes: ReadonlySet<string>;
}

export interface BashShellStateCheckpoint {
  readonly state: BashShellState;
  readonly environment: BranchCheckpoint;
}

export type BashShellScope = "current" | "subshell";

export interface CompletedShellState extends BashShellStatePatch {
  readonly scope: BashShellScope;
}

export function initialShellState(
  environment: Environment,
  imported: readonly BashFunction[] = [],
  cwd: string | null = null,
  cwdUncertain = false,
): BashShellState {
  return shellState(
    environment,
    new Map(imported.map((definition) => [definition.name, Object.freeze([definition])])),
    new Set(),
    cwd,
    cwdUncertain,
  );
}

export function withShellEnvironment(state: BashShellState, environment: Environment): BashShellState {
  return shellState(environment, state.functionCandidates, state.missingFunctions, state.cwd, state.cwdUncertain);
}

export function withShellCwd(state: BashShellState, cwd: string | null, cwdUncertain = cwd === null): BashShellState {
  return shellState(state.environment, state.functionCandidates, state.missingFunctions, cwd, cwdUncertain);
}

/**
 * Applies a directory-changing builtin. Only the cwd, its determinacy, and the
 * `PWD`/`OLDPWD` variables cd is defined to rewrite are affected; variable
 * bindings and shell functions are otherwise preserved. `PWD`/`OLDPWD` become
 * unknown because a static walker cannot prove the destination directory exists,
 * so a subsequent `$PWD` must not be trusted to hold a stale path. The shared
 * `cwd` stays null so relative file accesses keep deferring; `determinate`
 * distinguishes a destination the walker can name from one it cannot, which is
 * all command resolution needs.
 */
export function withDirectoryChange(state: BashShellState, determinate: boolean): BashShellState {
  const reason: UnknownReason = { kind: "directory-change" };
  const environment = assignNonLocalBinding(
    assignNonLocalBinding(state.environment, "PWD", unknown(reason)),
    "OLDPWD",
    unknown(reason),
  );
  return shellState(environment, state.functionCandidates, state.missingFunctions, null, !determinate);
}

export function defineShellFunction(state: BashShellState, definition: BashFunction): BashShellState {
  const functions = new Map(state.functionCandidates);
  const missing = new Set(state.missingFunctions);
  functions.set(definition.name, Object.freeze([definition]));
  missing.delete(definition.name);
  const exportedName = `BASH_FUNC_${definition.name}%%`;
  // Bash replaces an inherited export with the new body. Its exact serialized
  // text is not derivable from our CST; never leave the old body in a child env.
  const previous = lookupBinding(state.environment, exportedName);
  const environment =
    previous.value.kind !== "unset" && previous.exported
      ? assignBinding(state.environment, exportedName, unknown({ kind: "redefined-exported-function" }))
      : state.environment;
  return shellState(environment, functions, missing, state.cwd, state.cwdUncertain);
}

/** Mark a known function for export without inventing Bash's serialized text. */
export function exportShellFunction(state: BashShellState, name: string): BashShellState {
  if (!state.functionCandidates.has(name) || state.missingFunctions.has(name)) return state;
  const exportedName = `BASH_FUNC_${name}%%`;
  const old = lookupBinding(state.environment, exportedName);
  const environment =
    old.value.kind === "known" && old.exported
      ? state.environment
      : setExported(
          assignBinding(state.environment, exportedName, unknown({ kind: "exported-shell-function" })),
          exportedName,
          true,
        );
  return shellState(environment, state.functionCandidates, state.missingFunctions, state.cwd, state.cwdUncertain);
}

export function unexportShellFunction(state: BashShellState, name: string): BashShellState {
  const exportedName = `BASH_FUNC_${name}%%`;
  return shellState(
    unsetBinding(state.environment, exportedName),
    state.functionCandidates,
    state.missingFunctions,
    state.cwd,
    state.cwdUncertain,
  );
}

/** Record that a function definition is definitely absent after `unset -f`. */
export function removeShellFunction(state: BashShellState, name: string): BashShellState {
  const functions = new Map(state.functionCandidates);
  const missing = new Set(state.missingFunctions);
  functions.delete(name);
  missing.add(name);
  const exportedName = `BASH_FUNC_${name}%%`;
  const environment = hasBinding(state.environment, exportedName)
    ? unsetBinding(unsetBinding(state.environment, exportedName), inheritedBashFunctionFact(name))
    : state.environment;
  return shellState(environment, functions, missing, state.cwd, state.cwdUncertain);
}

/** Preserve a possible definition while allowing the name to resolve externally. */
export function invalidateShellFunction(state: BashShellState, name: string): BashShellState {
  if (!state.functionCandidates.has(name)) return state;
  return shellState(
    state.environment,
    state.functionCandidates,
    new Set([...state.missingFunctions, name]),
    state.cwd,
    state.cwdUncertain,
  );
}

/** A dynamic function name can remove any currently-known definition. */
export function invalidateShellFunctions(state: BashShellState): BashShellState {
  return shellState(
    state.environment,
    state.functionCandidates,
    new Set([...state.missingFunctions, ...state.functionCandidates.keys()]),
    state.cwd,
    state.cwdUncertain,
  );
}

/** Preserve possible prior definitions while invalidating caller-visible facts. */
export function taintShellState(state: BashShellState, reason: UnknownReason): BashShellState {
  return shellState(
    taintFrame(state.environment, reason),
    state.functionCandidates,
    new Set([...state.missingFunctions, ...state.functionCandidates.keys()]),
    null,
    true,
  );
}

export function forkShellState(state: BashShellState): BashShellStateCheckpoint {
  return Object.freeze({ state, environment: forkCheckpoint(state.environment) });
}

/** Conservatively joins every caller-visible shell-state domain. */
export function joinShellStates(
  checkpoint: BashShellStateCheckpoint,
  branches: readonly BashShellStatePatch[],
): BashShellState {
  if (branches.length === 0) return checkpoint.state;

  const environment = mergeCheckpoint(
    checkpoint.environment,
    branches.map((branch) => ({ environment: branch.state.environment, writes: branch.writes })),
  );
  const functions = new Map<string, BashFunction[]>();
  const names = new Set<string>();
  const missing = new Set<string>();

  for (const branch of branches) {
    for (const name of branch.state.functionCandidates.keys()) names.add(name);
    for (const [name, definitions] of branch.state.functionCandidates) {
      const candidates = functions.get(name) ?? [];
      for (const definition of definitions) if (!candidates.includes(definition)) candidates.push(definition);
      functions.set(name, candidates);
    }
  }
  for (const name of names) {
    if (
      branches.some((branch) => !branch.state.functionCandidates.has(name) || branch.state.missingFunctions.has(name))
    ) {
      missing.add(name);
    }
  }
  const cwd = branches.every((branch) => branch.state.cwd === branches[0]!.state.cwd) ? branches[0]!.state.cwd : null;
  const cwdUncertain =
    branches.some((branch) => branch.state.cwdUncertain) ||
    branches.some((branch) => branch.state.cwd !== branches[0]!.state.cwd);
  return shellState(environment, functions, missing, cwd, cwdUncertain);
}

/** Current-scope children propagate complete state; subshell children leak none. */
export function completeShellState(parent: BashShellState, children: readonly CompletedShellState[]): BashShellState {
  const current = children.filter((child) => child.scope === "current");
  return current.length === 0 ? parent : joinShellStates(forkShellState(parent), current);
}

function shellState(
  environment: Environment,
  functionCandidates: ReadonlyMap<string, readonly BashFunction[]>,
  missingFunctions: ReadonlySet<string>,
  cwd: string | null,
  cwdUncertain: boolean,
): BashShellState {
  return Object.freeze({ environment, functionCandidates, missingFunctions, cwd, cwdUncertain });
}
