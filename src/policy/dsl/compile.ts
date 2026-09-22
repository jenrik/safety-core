import type {
  Expression,
  OptionDeclaration,
  PolicyCase,
  PolicyDocument,
  TerminalAction,
} from "./ast.js";
import { POLICY_DOCUMENT_LIMITS } from "./validate.js";

export interface CompiledTransitionAction {
  readonly kind: "transition";
  readonly consume: "word";
  readonly progress: 1;
  readonly next: string;
  readonly set: Readonly<Record<string, Expression>>;
  readonly fold: readonly string[];
}

/**
 * An option action retains its complete finite grammar for the evaluator. A
 * matched form consumes one word, an optional following word, or one or more
 * bytes from that finite word; minProgress proves every form moves forward.
 */
export interface CompiledOptionAction {
  readonly kind: "option";
  readonly option: string;
  readonly names: readonly string[];
  readonly value: OptionDeclaration["value"];
  readonly forms: OptionDeclaration["forms"];
  readonly minProgress: 1;
  /** A cluster form advances the active finite option word by at least one byte. */
  readonly clusterByteProgress: boolean;
  readonly next: string;
  readonly set: Readonly<Record<string, Expression>>;
  readonly fold: readonly string[];
}

export interface CompiledTerminalAction extends TerminalAction {
  readonly kind: "terminal";
}

export type CompiledAction = CompiledTransitionAction | CompiledOptionAction | CompiledTerminalAction;
export interface CompiledOptionPredicate { readonly kind: "option"; readonly option: string; }
export interface CompiledCase {
  readonly when: Expression | CompiledOptionPredicate;
  readonly action: CompiledAction;
  readonly origin: `option:${string}` | `state:${string}` | `fragment:${string}`;
}

export interface CompiledState {
  readonly cases: readonly CompiledCase[];
  readonly default: CompiledTerminalAction;
  readonly end: CompiledTerminalAction;
}

export interface CompiledPolicyProgram {
  readonly language: PolicyDocument["language"];
  readonly layer: PolicyDocument["layer"];
  readonly select: PolicyDocument["select"];
  readonly registers: PolicyDocument["registers"];
  readonly folds: PolicyDocument["folds"];
  /** Full ordered option declarations; no form/value grammar is discarded. */
  readonly options: PolicyDocument["options"];
  readonly start: string;
  readonly states: Readonly<Record<string, CompiledState>>;
  readonly metrics: Readonly<{ readonly states: number; readonly transitions: number; readonly cases: number }>;
}

interface FragmentPlan {
  readonly cases: ReadonlyMap<string, number>;
  readonly transitions: ReadonlyMap<string, number>;
}

interface OrderedOption {
  readonly name: string;
  readonly declaration: OptionDeclaration;
  readonly order: number;
}

interface OptionIndex {
  readonly machineWide: readonly OrderedOption[];
  readonly local: ReadonlyMap<string, readonly OrderedOption[]>;
  readonly totalInstances: number;
}

/** Lower ordered options and acyclic fragments only after proving their finite expansion size. */
export function compilePolicyDocument(ast: PolicyDocument): CompiledPolicyProgram {
  const fragments = planFragments(ast);
  const options = indexOptions(ast);
  assertCompiledBounds(ast, fragments, options);

  const states: Record<string, CompiledState> = {};
  let transitions = 0;
  let cases = 0;
  for (const [stateName, state] of Object.entries(ast.states)) {
    const lowered: CompiledCase[] = [];
    for (const option of applicableOptions(stateName, options)) {
      lowered.push(Object.freeze({
        when: Object.freeze({ kind: "option", option: option.name }),
        action: optionAction(option, stateName),
        origin: `option:${option.name}`,
      }));
      transitions++;
    }
    for (const fragmentName of state.fragments) {
      for (const entry of expandFragment(ast, fragmentName)) {
        lowered.push(lowerCase(entry.policyCase, `fragment:${entry.origin}`));
        if (entry.policyCase.action.kind === "transition") transitions++;
      }
    }
    for (const entry of state.cases) {
      lowered.push(lowerCase(entry, `state:${stateName}`));
      if (entry.action.kind === "transition") transitions++;
    }
    cases += lowered.length;
    states[stateName] = Object.freeze({ cases: Object.freeze(lowered), default: state.default, end: state.end });
  }

  const program: CompiledPolicyProgram = Object.freeze({
    language: ast.language,
    layer: ast.layer,
    select: ast.select,
    registers: ast.registers,
    folds: ast.folds,
    options: ast.options,
    start: ast.start,
    states: Object.freeze(states),
    metrics: Object.freeze({ states: Object.keys(states).length, transitions, cases }),
  });
  assertCompiledProgress(program);
  return program;
}

function optionAction(option: OrderedOption, state: string): CompiledOptionAction {
  return Object.freeze({
    kind: "option",
    option: option.name,
    names: option.declaration.names,
    value: option.declaration.value,
    forms: option.declaration.forms,
    minProgress: 1,
    clusterByteProgress: option.declaration.forms.includes("cluster"),
    next: state,
    set: option.declaration.set,
    fold: Object.freeze([]),
  });
}

function lowerCase(policyCase: PolicyCase, origin: CompiledCase["origin"]): CompiledCase {
  return Object.freeze({
    when: policyCase.when,
    action: policyCase.action.kind === "terminal"
      ? policyCase.action
      : Object.freeze({ kind: "transition", consume: "word", progress: 1, next: policyCase.action.next, set: policyCase.action.set, fold: policyCase.action.fold }),
    origin,
  });
}

function expandFragment(ast: PolicyDocument, name: string): readonly { readonly policyCase: PolicyCase; readonly origin: string }[] {
  const fragment = ast.fragments[name];
  if (!fragment) throw new TypeError(`cannot compile unknown fragment ${name}`);
  return Object.freeze([
    ...fragment.uses.flatMap((used) => expandFragment(ast, used)),
    ...fragment.cases.map((policyCase) => Object.freeze({ policyCase, origin: name })),
  ]);
}

/** Structural, saturating expansion accounting; shared references count once per use site. */
function planFragments(ast: PolicyDocument): FragmentPlan {
  const cases = new Map<string, number>();
  const transitions = new Map<string, number>();
  const visiting = new Set<string>();
  const visit = (name: string): void => {
    if (cases.has(name)) return;
    if (visiting.has(name)) throw new TypeError(`cannot compile cyclic fragment ${name}`);
    const fragment = ast.fragments[name];
    if (!fragment) throw new TypeError(`cannot compile unknown fragment ${name}`);
    visiting.add(name);
    let caseCount = fragment.cases.length;
    let transitionCount = fragment.cases.filter((entry) => entry.action.kind === "transition").length;
    for (const used of fragment.uses) {
      visit(used);
      caseCount = saturatingAdd(caseCount, cases.get(used)!);
      transitionCount = saturatingAdd(transitionCount, transitions.get(used)!);
    }
    visiting.delete(name);
    cases.set(name, caseCount);
    transitions.set(name, transitionCount);
  };
  for (const name of Object.keys(ast.fragments)) visit(name);
  return { cases, transitions };
}

function indexOptions(ast: PolicyDocument): OptionIndex {
  const machineWide: OrderedOption[] = [];
  const local = new Map<string, OrderedOption[]>();
  let order = 0;
  for (const [name, declaration] of Object.entries(ast.options)) {
    const option = Object.freeze({ name, declaration, order: order++ });
    if (declaration.availableIn === "*") {
      machineWide.push(option);
      continue;
    }
    for (const state of declaration.availableIn) {
      const entries = local.get(state) ?? [];
      entries.push(option);
      local.set(state, entries);
    }
  }
  let totalInstances = machineWide.length * Object.keys(ast.states).length;
  for (const entries of local.values()) totalInstances += entries.length;
  return { machineWide, local, totalInstances };
}

function applicableOptions(state: string, index: OptionIndex): readonly OrderedOption[] {
  const local = index.local.get(state) ?? [];
  const result: OrderedOption[] = [];
  let machineIndex = 0;
  let localIndex = 0;
  while (machineIndex < index.machineWide.length || localIndex < local.length) {
    const machine = index.machineWide[machineIndex];
    const stateLocal = local[localIndex];
    if (!stateLocal || (machine !== undefined && machine.order < stateLocal.order)) {
      result.push(machine!);
      machineIndex++;
    } else {
      result.push(stateLocal);
      localIndex++;
    }
  }
  return result;
}

function assertCompiledBounds(ast: PolicyDocument, fragments: FragmentPlan, options: OptionIndex): void {
  let cases = options.totalInstances;
  let transitions = options.totalInstances;
  for (const state of Object.values(ast.states)) {
    cases = saturatingAdd(cases, state.cases.length);
    transitions = saturatingAdd(transitions, state.cases.filter((entry) => entry.action.kind === "transition").length);
    for (const fragment of state.fragments) {
      cases = saturatingAdd(cases, fragments.cases.get(fragment) ?? POLICY_DOCUMENT_LIMITS.expandedCases + 1);
      transitions = saturatingAdd(transitions, fragments.transitions.get(fragment) ?? POLICY_DOCUMENT_LIMITS.transitions + 1);
    }
  }
  if (cases > POLICY_DOCUMENT_LIMITS.expandedCases || transitions > POLICY_DOCUMENT_LIMITS.transitions) {
    throw new TypeError("compiled policy exceeds fixed transition or expanded case limits");
  }
}

function saturatingAdd(left: number, right: number): number {
  const limit = Math.max(POLICY_DOCUMENT_LIMITS.expandedCases, POLICY_DOCUMENT_LIMITS.transitions) + 1;
  return left > limit - right ? limit : left + right;
}

function assertCompiledProgress(program: CompiledPolicyProgram): void {
  for (const [stateName, state] of Object.entries(program.states)) {
    if (state.default.kind !== "terminal" || state.end.kind !== "terminal") throw new TypeError(`compiled state ${stateName} lacks terminal default/end behavior`);
    for (const [index, entry] of state.cases.entries()) {
      if (entry.action.kind === "transition" && entry.action.progress !== 1) throw new TypeError(`compiled transition ${stateName}.cases[${index}] does not consume a word`);
      if (entry.action.kind === "option" && entry.action.minProgress !== 1) throw new TypeError(`compiled option ${stateName}.cases[${index}] does not consume input`);
      if (entry.action.kind === "option" && entry.action.forms.includes("cluster") && !entry.action.clusterByteProgress) {
        throw new TypeError(`compiled cluster option ${stateName}.cases[${index}] does not consume a byte`);
      }
    }
  }
}
