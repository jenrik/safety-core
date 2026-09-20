import type { BashFunction } from "./cst.js";
import {
  forkCheckpoint,
  mergeCheckpoint,
  taintFrame,
  type BranchCheckpoint,
  type Environment,
  type UnknownReason,
} from "./environment.js";

/** Every abstract shell fact visible to later commands in the current scope. */
export interface BashShellState {
  readonly environment: Environment;
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

export function initialShellState(environment: Environment): BashShellState {
  return shellState(environment, new Map(), new Set());
}

export function withShellEnvironment(state: BashShellState, environment: Environment): BashShellState {
  return shellState(environment, state.functionCandidates, state.missingFunctions);
}

export function defineShellFunction(state: BashShellState, definition: BashFunction): BashShellState {
  const functions = new Map(state.functionCandidates);
  const missing = new Set(state.missingFunctions);
  functions.set(definition.name, Object.freeze([definition]));
  missing.delete(definition.name);
  return shellState(state.environment, functions, missing);
}

/** Record that a function definition is definitely absent after `unset -f`. */
export function removeShellFunction(state: BashShellState, name: string): BashShellState {
  const functions = new Map(state.functionCandidates);
  const missing = new Set(state.missingFunctions);
  functions.delete(name);
  missing.add(name);
  return shellState(state.environment, functions, missing);
}

/** Preserve a possible definition while allowing the name to resolve externally. */
export function invalidateShellFunction(state: BashShellState, name: string): BashShellState {
  if (!state.functionCandidates.has(name)) return state;
  return shellState(state.environment, state.functionCandidates, new Set([...state.missingFunctions, name]));
}

/** A dynamic function name can remove any currently-known definition. */
export function invalidateShellFunctions(state: BashShellState): BashShellState {
  return shellState(
    state.environment,
    state.functionCandidates,
    new Set([...state.missingFunctions, ...state.functionCandidates.keys()]),
  );
}

/** Preserve possible prior definitions while invalidating caller-visible facts. */
export function taintShellState(state: BashShellState, reason: UnknownReason): BashShellState {
  return shellState(
    taintFrame(state.environment, reason),
    state.functionCandidates,
    new Set([...state.missingFunctions, ...state.functionCandidates.keys()]),
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
    if (branches.some((branch) => !branch.state.functionCandidates.has(name) || branch.state.missingFunctions.has(name))) {
      missing.add(name);
    }
  }
  return shellState(environment, functions, missing);
}

/** Current-scope children propagate complete state; subshell children leak none. */
export function completeShellState(
  parent: BashShellState,
  children: readonly CompletedShellState[],
): BashShellState {
  const current = children.filter((child) => child.scope === "current");
  return current.length === 0 ? parent : joinShellStates(forkShellState(parent), current);
}

function shellState(
  environment: Environment,
  functionCandidates: ReadonlyMap<string, readonly BashFunction[]>,
  missingFunctions: ReadonlySet<string>,
): BashShellState {
  return Object.freeze({ environment, functionCandidates, missingFunctions });
}
