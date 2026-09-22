import type { SourceSpan } from "./cst.js";

const DELTA_COMPACTION_THRESHOLD = 32;

export interface UnknownReason {
  readonly kind: string;
  readonly span?: SourceSpan;
}

export type BindingValue =
  | { readonly kind: "known"; readonly value: string }
  | { readonly kind: "unknown"; readonly reason: UnknownReason }
  | { readonly kind: "unset" };

export interface Binding {
  readonly value: BindingValue;
  readonly exported: boolean;
  readonly readonly: boolean;
}

/** A scope identity. Its implementation state is held privately and immutable. */
export interface Frame {
  readonly parent?: Frame;
}

export interface Budgets {
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  readonly steps: number;
  readonly workItems: number;
}

export interface Environment {
  readonly frame: Frame;
  readonly overlay?: Frame;
  readonly budgets: Budgets;
  /** Whether names absent from a verified initial snapshot are known unset. */
  readonly missingBindings: "unknown" | "unset";
}

export interface BranchCheckpoint {
  readonly base: Environment;
  readonly writes: ReadonlySet<string>;
}

export interface EnvironmentPatch {
  readonly environment: Environment;
  readonly writes: ReadonlySet<string>;
}

/** Complete materialization of modeled bindings and the semantics of absent names. */
export interface ModeledBindings {
  readonly values: Readonly<Record<string, BindingValue>>;
  readonly missingBindings: Environment["missingBindings"];
}

interface FrameState {
  readonly parent?: Frame;
  readonly previous?: Frame;
  readonly delta: ReadonlyMap<string, Binding>;
  readonly kind: FrameKind;
  readonly localNames: ReadonlySet<string>;
  readonly taint?: UnknownReason;
  readonly taintVersion?: TaintVersion;
  readonly writesSinceTaint: ReadonlySet<string>;
  readonly depth: number;
  /** Positive positional parameters stop at this dynamic call boundary. */
  readonly positionalParametersLocal: boolean;
}

interface TaintVersion {}
type FrameKind = "shell" | "function" | "subshell" | "overlay";

const frameStates = new WeakMap<Frame, FrameState>();
const DEFAULT_BUDGETS: Budgets = Object.freeze({
  functionDepth: 128,
  nestedScriptDepth: 64,
  steps: 7_500,
  workItems: 10_000,
});
const UNSET: BindingValue = Object.freeze({ kind: "unset" });

export function known(value: string): BindingValue {
  return Object.freeze({ kind: "known", value });
}

export function unknown(reason: UnknownReason): BindingValue {
  return Object.freeze({ kind: "unknown", reason: freezeReason(reason) });
}

export function unset(): BindingValue {
  return UNSET;
}

export function fromInitialEnvironment(
  initial: Readonly<Record<string, string | Binding | BindingValue>> = {},
  budgets: Partial<Budgets> = {},
  missingBindings: Environment["missingBindings"] = "unknown",
): Environment {
  const bindings = new Map<string, Binding>();
  for (const [name, value] of Object.entries(initial)) bindings.set(name, normalizeBinding(value));
  return createEnvironment(createFrame(undefined, undefined, bindings), undefined, { ...DEFAULT_BUDGETS, ...budgets }, missingBindings);
}

/** A complete, harness-verified process environment where absent names are unset. */
export function fromVerifiedInitialEnvironment(
  initial: Readonly<Record<string, string | Binding | BindingValue>> = {},
  budgets: Partial<Budgets> = {},
): Environment {
  const exported = Object.fromEntries(Object.entries(initial).map(([name, value]) => [name, {
    value: typeof value === "string" ? known(value) : "value" in value ? value.value : value,
    exported: true,
    readonly: false,
  }])) as Readonly<Record<string, Binding>>;
  return fromInitialEnvironment(exported, budgets, "unset");
}

/** A value-filtered process snapshot where only listed absences are proven unset. */
export function fromFilteredInitialEnvironment(
  initial: Readonly<Record<string, string | Binding | BindingValue>> = {},
  unsetNames: readonly string[] = [],
  budgets: Partial<Budgets> = {},
): Environment {
  const bindings = Object.fromEntries(Object.entries(initial).map(([name, value]) => [name, {
    value: typeof value === "string" ? known(value) : "value" in value ? value.value : value,
    exported: true,
    readonly: false,
  }])) as Record<string, Binding>;
  for (const name of unsetNames) {
    if (!(name in bindings)) bindings[name] = createBinding(unset(), false, false);
  }
  return fromInitialEnvironment(bindings, budgets, "unknown");
}

export function lookupBinding(environment: Environment, name: string): Binding {
  return lookupInFrame(environment.overlay ?? environment.frame, name)
    ?? createBinding(unset(), false, false);
}

/** Distinguishes an explicit `unset` from a name missing in an unavailable environment. */
export function hasBinding(environment: Environment, name: string): boolean {
  const target = environment.overlay ?? environment.frame;
  if (lookupInFrame(target, name) !== undefined) return true;
  for (let current: Frame | undefined = target; current; current = stateFor(current).parent) {
    if (stateFor(current).positionalParametersLocal && isPositivePositionalParameter(name)) return true;
  }
  return false;
}

/**
 * Materialize every binding the model currently knows, preserving values and
 * uncertainty for policy evaluation without exposing mutable frame internals.
 */
export function modeledBindings(environment: Environment): ModeledBindings {
  const names = new Set<string>();
  const collect = (frame: Frame | undefined): void => {
    if (!frame) return;
    const state = stateFor(frame);
    collect(state.parent);
    const own = collectOwnBindings(frame);
    for (const name of own.keys()) names.add(name);
  };
  collect(environment.overlay ?? environment.frame);
  return Object.freeze({
    values: Object.freeze(Object.fromEntries([...names].map((name) => [name, lookupBinding(environment, name).value]))),
    missingBindings: environment.missingBindings,
  });
}

export function assignBinding(environment: Environment, name: string, value: BindingValue): Environment {
  if (stateFor(environment.overlay ?? environment.frame).kind === "function") {
    return assignNonLocalBinding(environment, name, value);
  }
  const previous = lookupBinding(environment, name);
  return writeBinding(environment, name, createBinding(value, previous.exported, previous.readonly));
}

/** Creates a function-local shadow without modifying a caller-visible binding. */
export function assignLocalBinding(environment: Environment, name: string, value: BindingValue): Environment {
  const target = environment.overlay ?? environment.frame;
  const previous = lookupOwnBinding(target, name) ?? createBinding(unset(), false, false);
  return writeBinding(environment, name, createBinding(value, previous.exported, previous.readonly), true);
}

/** Writes the nearest dynamically visible binding, creating one in the outer shell if absent. */
export function assignNonLocalBinding(environment: Environment, name: string, value: BindingValue): Environment {
  const target = environment.overlay ?? environment.frame;
  const destination = findNearestBindingScope(target, name) ?? outermostScope(target);
  const previous = lookupOwnBinding(destination, name) ?? createBinding(unset(), false, false);
  const updatedDestination = writeFrame(destination, name, createBinding(value, previous.exported, previous.readonly));
  const updatedTarget = destination === target
    ? updatedDestination
    : replaceAncestorFrame(target, destination, updatedDestination);
  return replaceActiveFrame(environment, updatedTarget);
}

export function unsetBinding(environment: Environment, name: string): Environment {
  return writeVisibleBinding(environment, name, (previous) => createBinding(unset(), previous.exported, previous.readonly));
}

export function setExported(environment: Environment, name: string, exported: boolean): Environment {
  return writeVisibleBinding(environment, name, (previous) => createBinding(previous.value, exported, previous.readonly));
}

export function setReadonly(environment: Environment, name: string, readonly: boolean): Environment {
  return writeVisibleBinding(environment, name, (previous) => createBinding(previous.value, previous.exported, readonly));
}

export function pushFunctionFrame(environment: Environment): Environment {
  return createEnvironment(
    createFrame(environment.overlay ?? environment.frame, undefined, new Map(), undefined, new ImmutableSet(), undefined, "function", new ImmutableSet(), true),
    undefined,
    environment.budgets,
    environment.missingBindings,
  );
}

/** Creates an interpreter-call boundary whose omitted `$N` values are unset. */
export function pushPositionalFrame(environment: Environment): Environment {
  return createEnvironment(
    createFrame(environment.overlay ?? environment.frame, undefined, new Map(), undefined, new ImmutableSet(), undefined, "subshell", new ImmutableSet(), true),
    undefined,
    environment.budgets,
    environment.missingBindings,
  );
}

export function pushSubshellFrame(environment: Environment): Environment {
  return createEnvironment(
    createFrame(environment.overlay ?? environment.frame, undefined, new Map(), undefined, new ImmutableSet(), undefined, "subshell"),
    undefined,
    environment.budgets,
    environment.missingBindings,
  );
}

/** Leaves a function frame while retaining any reconstructed caller frames. */
export function returnFromFunctionFrame(environment: Environment): Environment {
  const frame = environment.overlay ?? environment.frame;
  const state = stateFor(frame);
  if (state.kind !== "function") return environment;
  if (!state.parent) throw new Error("Function frame has no caller frame");
  return createEnvironment(state.parent, undefined, environment.budgets, environment.missingBindings);
}

export function beginCommandOverlay(environment: Environment): Environment {
  if (environment.overlay) return environment;
  return createEnvironment(
    environment.frame,
    createFrame(environment.frame, undefined, new Map(), undefined, new ImmutableSet(), undefined, "overlay"),
    environment.budgets,
    environment.missingBindings,
  );
}

export function endCommandOverlay(environment: Environment): Environment {
  return environment.overlay ? createEnvironment(environment.frame, undefined, environment.budgets, environment.missingBindings) : environment;
}

export function forkCheckpoint(base: Environment): BranchCheckpoint {
  return Object.freeze({ base, writes: new ImmutableSet<string>() });
}

export function recordWrite(checkpoint: BranchCheckpoint, name: string): BranchCheckpoint {
  return Object.freeze({ base: checkpoint.base, writes: new ImmutableSet(checkpoint.writes, name) });
}

export function mergeCheckpoint(checkpoint: BranchCheckpoint, branches: readonly EnvironmentPatch[]): Environment {
  if (branches.length === 0) return checkpoint.base;

  const names = new Set<string>();
  for (const branch of branches) for (const name of branch.writes) names.add(name);

  const hasNewTaint = branches.some((branch) => hasTaintSince(branch.environment, checkpoint.base));
  let merged = hasNewTaint ? taintFrame(checkpoint.base) : checkpoint.base;

  for (const name of names) {
    const bindings = branches.map((branch) => lookupBinding(branch.environment, name));
    const first = bindings[0]!;
    const next = bindings.every((binding) => bindingsEqual(binding, first))
      ? first
      : createBinding(
        unknown({ kind: "branch-disagreement" }),
        bindings.every((binding) => binding.exported),
        bindings.every((binding) => binding.readonly),
      );
    merged = writeBinding(merged, name, next);
  }

  return merged;
}

/** Conservatively weakens all existing and future implicit lookups in this frame. */
export function taintFrame(environment: Environment, reason: UnknownReason = { kind: "arbitrary-mutation" }): Environment {
  const target = environment.overlay ?? environment.frame;
  const state = stateFor(target);
  const tainted = createFrame(
    state.parent,
    target,
    new Map(),
    freezeReason(reason),
    new ImmutableSet<string>(),
    Object.freeze({}),
    state.kind,
    state.localNames,
    state.positionalParametersLocal,
  );
  return environment.overlay
    ? createEnvironment(environment.frame, tainted, environment.budgets, environment.missingBindings)
    : createEnvironment(tainted, undefined, environment.budgets, environment.missingBindings);
}

function createEnvironment(
  frame: Frame,
  overlay: Frame | undefined,
  budgets: Budgets,
  missingBindings: Environment["missingBindings"],
): Environment {
  return Object.freeze({ frame, ...(overlay ? { overlay } : {}), budgets: Object.freeze({ ...budgets }), missingBindings });
}

function writeBinding(environment: Environment, name: string, binding: Binding): Environment {
  const target = environment.overlay ?? environment.frame;
  return replaceActiveFrame(environment, writeFrame(target, name, binding));
}

/** Builtin attributes and unset affect the nearest dynamically visible name. */
function writeVisibleBinding(environment: Environment, name: string, update: (binding: Binding) => Binding): Environment {
  const target = environment.overlay ?? environment.frame;
  const destination = findNearestBindingScope(target, name) ?? outermostScope(target);
  const previous = lookupOwnBinding(destination, name) ?? createBinding(unset(), false, false);
  const updatedDestination = writeFrame(destination, name, update(previous));
  const updatedTarget = destination === target
    ? updatedDestination
    : replaceAncestorFrame(target, destination, updatedDestination);
  return replaceActiveFrame(environment, updatedTarget);
}

function writeFrame(frame: Frame, name: string, binding: Binding, markLocal = false): Frame {
  const state = stateFor(frame);
  const localNames = markLocal ? new ImmutableSet(state.localNames, name) : state.localNames;
  const writesSinceTaint = state.taint
    ? new ImmutableSet(state.writesSinceTaint, name)
    : state.writesSinceTaint;
  return maybeCompact(createFrame(
    state.parent,
    frame,
    new Map([[name, binding]]),
    state.taint,
    writesSinceTaint,
    state.taintVersion,
    state.kind,
    localNames,
    state.positionalParametersLocal,
  ));
}

function replaceActiveFrame(environment: Environment, frame: Frame): Environment {
  return environment.overlay
    ? createEnvironment(environment.frame, frame, environment.budgets, environment.missingBindings)
    : createEnvironment(frame, undefined, environment.budgets, environment.missingBindings);
}

function findNearestBindingScope(frame: Frame, name: string): Frame | undefined {
  for (let current: Frame | undefined = frame; current; current = stateFor(current).parent) {
    if (lookupOwnBinding(current, name)) return current;
  }
  return undefined;
}

function outermostScope(frame: Frame): Frame {
  let current = frame;
  while (stateFor(current).parent) current = stateFor(current).parent!;
  return current;
}

function replaceAncestorFrame(frame: Frame, target: Frame, replacement: Frame): Frame {
  if (frame === target) return replacement;
  const state = stateFor(frame);
  if (!state.parent) throw new Error("Target frame is not a dynamic ancestor");
  return copyFrameWithParent(frame, replaceAncestorFrame(state.parent, target, replacement));
}

function copyFrameWithParent(frame: Frame, parent: Frame): Frame {
  const state = stateFor(frame);
  return createFrame(
    parent,
    undefined,
    collectOwnBindings(frame),
    state.taint,
    state.writesSinceTaint,
    state.taintVersion,
    state.kind,
    state.localNames,
    state.positionalParametersLocal,
  );
}

function lookupInFrame(frame: Frame, name: string): Binding | undefined {
  for (let current: Frame | undefined = frame; current; current = stateFor(current).previous) {
    const state = stateFor(current);
    if (state.taint && !state.writesSinceTaint.has(name)) {
      return createBinding(unknown(state.taint), false, false);
    }
    const binding = state.delta.get(name);
    if (binding) return binding;
    if (!state.previous) {
      if (state.positionalParametersLocal && isPositivePositionalParameter(name)) return undefined;
      return state.parent ? lookupInFrame(state.parent, name) : undefined;
    }
  }
  return undefined;
}

function lookupOwnBinding(frame: Frame, name: string): Binding | undefined {
  for (let current: Frame | undefined = frame; current; current = stateFor(current).previous) {
    const binding = stateFor(current).delta.get(name);
    if (binding) return binding;
  }
  return undefined;
}

function createFrame(
  parent: Frame | undefined,
  previous?: Frame,
  delta: ReadonlyMap<string, Binding> = new Map(),
  taint?: UnknownReason,
  writesSinceTaint: ReadonlySet<string> = new ImmutableSet<string>(),
  taintVersion?: TaintVersion,
  kind: FrameKind = "shell",
  localNames: ReadonlySet<string> = new ImmutableSet<string>(),
  positionalParametersLocal = false,
): Frame {
  const frame: Frame = Object.freeze(parent ? { parent } : {});
  const previousState = previous ? stateFor(previous) : undefined;
  frameStates.set(frame, {
    parent,
    previous,
    delta: new ImmutableMap(delta),
    kind,
    localNames: new ImmutableSet(localNames),
    taint,
    taintVersion,
    writesSinceTaint: new ImmutableSet(writesSinceTaint),
    depth: (previousState?.depth ?? 0) + 1,
    positionalParametersLocal,
  });
  return frame;
}

function maybeCompact(frame: Frame): Frame {
  const state = stateFor(frame);
  if (state.depth <= DELTA_COMPACTION_THRESHOLD) return frame;

  const bindings = new Map<string, Binding>();
  for (let current: Frame | undefined = frame; current; current = stateFor(current).previous) {
    for (const [name, binding] of stateFor(current).delta) {
      if (!bindings.has(name)) bindings.set(name, binding);
    }
  }
  return createFrame(
    state.parent,
    undefined,
    bindings,
    state.taint,
    state.writesSinceTaint,
    state.taintVersion,
    state.kind,
    state.localNames,
    state.positionalParametersLocal,
  );
}

function collectOwnBindings(frame: Frame): ReadonlyMap<string, Binding> {
  const bindings = new Map<string, Binding>();
  for (let current: Frame | undefined = frame; current; current = stateFor(current).previous) {
    for (const [name, binding] of stateFor(current).delta) {
      if (!bindings.has(name)) bindings.set(name, binding);
    }
  }
  return bindings;
}

function hasTaintSince(environment: Environment, base: Environment): boolean {
  const branchState = stateFor(environment.overlay ?? environment.frame);
  const baseState = stateFor(base.overlay ?? base.frame);
  return branchState.taintVersion !== undefined && branchState.taintVersion !== baseState.taintVersion;
}

function normalizeBinding(value: string | Binding | BindingValue): Binding {
  if (typeof value === "string") return createBinding(known(value), false, false);
  if ("exported" in value && "readonly" in value) return createBinding(value.value, value.exported, value.readonly);
  return createBinding(value, false, false);
}

function createBinding(value: BindingValue, exported: boolean, readonly: boolean): Binding {
  return Object.freeze({ value: freezeValue(value), exported, readonly });
}

function freezeValue(value: BindingValue): BindingValue {
  if (value.kind === "unknown") return unknown(value.reason);
  if (value.kind === "known") return known(value.value);
  return unset();
}

function freezeReason(reason: UnknownReason): UnknownReason {
  return Object.freeze(reason.span
    ? { kind: reason.kind, span: Object.freeze({ start: reason.span.start, end: reason.span.end }) }
    : { kind: reason.kind });
}

function bindingsEqual(left: Binding, right: Binding): boolean {
  return left.exported === right.exported
    && left.readonly === right.readonly
    && valuesEqual(left.value, right.value);
}

function isPositivePositionalParameter(name: string): boolean {
  return /^[1-9][0-9]*$/.test(name);
}

function valuesEqual(left: BindingValue, right: BindingValue): boolean {
  if (left.kind !== right.kind) return false;
  if (left.kind === "known" && right.kind === "known") return left.value === right.value;
  if (left.kind === "unknown" && right.kind === "unknown") {
    return left.reason.kind === right.reason.kind
      && left.reason.span?.start === right.reason.span?.start
      && left.reason.span?.end === right.reason.span?.end;
  }
  return true;
}

function stateFor(frame: Frame): FrameState {
  const state = frameStates.get(frame);
  if (!state) throw new Error("Unknown environment frame");
  return state;
}

class ImmutableSet<T> implements ReadonlySet<T> {
  readonly #values: Set<T>;

  constructor(values: Iterable<T> = [], extra?: T) {
    this.#values = new Set(values);
    if (extra !== undefined) this.#values.add(extra);
    Object.freeze(this);
  }

  get size(): number { return this.#values.size; }
  has(value: T): boolean { return this.#values.has(value); }
  entries(): SetIterator<[T, T]> { return this.#values.entries(); }
  keys(): SetIterator<T> { return this.#values.keys(); }
  values(): SetIterator<T> { return this.#values.values(); }
  forEach(callbackfn: (value: T, value2: T, set: ReadonlySet<T>) => void, thisArg?: unknown): void {
    this.#values.forEach((value) => callbackfn.call(thisArg, value, value, this));
  }
  [Symbol.iterator](): SetIterator<T> { return this.#values[Symbol.iterator](); }
}

class ImmutableMap<K, V> implements ReadonlyMap<K, V> {
  readonly #values: Map<K, V>;

  constructor(values: ReadonlyMap<K, V>) {
    this.#values = new Map(values);
    Object.freeze(this);
  }

  get size(): number { return this.#values.size; }
  get(key: K): V | undefined { return this.#values.get(key); }
  has(key: K): boolean { return this.#values.has(key); }
  entries(): MapIterator<[K, V]> { return this.#values.entries(); }
  keys(): MapIterator<K> { return this.#values.keys(); }
  values(): MapIterator<V> { return this.#values.values(); }
  forEach(callbackfn: (value: V, key: K, map: ReadonlyMap<K, V>) => void, thisArg?: unknown): void {
    this.#values.forEach((value, key) => callbackfn.call(thisArg, value, key, this));
  }
  [Symbol.iterator](): MapIterator<[K, V]> { return this.#values[Symbol.iterator](); }
}
