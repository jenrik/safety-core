import type {
  Action,
  Expression,
  OptionDeclaration,
  PolicyCase,
  PolicyDocument,
  TerminalAction,
} from "./ast.js";
import { POLICY_DOCUMENT_LIMITS } from "./validate.js";

export interface CompiledTransitionAction {
  readonly kind: "transition";
  readonly consume: "word" | "cluster-byte";
  /** Strictly positive decrease in remaining token-boundary-plus-byte measure. */
  readonly progress: number;
  readonly next: string;
  readonly set: Readonly<Record<string, Expression>>;
  readonly fold: readonly string[];
}

export interface CompiledTerminalAction extends TerminalAction {
  readonly kind: "terminal";
}

export type CompiledAction = CompiledTransitionAction | CompiledTerminalAction;
/** Compiler-only option matcher; it cannot be authored as a regular expression call. */
export interface CompiledOptionPredicate {
  readonly kind: "option";
  readonly option: string;
}
export interface CompiledCase {
  readonly when: Expression | CompiledOptionPredicate;
  readonly action: CompiledAction;
  readonly origin: `option:${string}` | `state:${string}` | `fragment:${string}` | `cluster:${string}`;
}

export interface CompiledState {
  readonly cases: readonly CompiledCase[];
  readonly default: CompiledTerminalAction;
  readonly end: CompiledTerminalAction;
}

export interface CompiledClusterState {
  readonly state: string;
  readonly option: string;
  readonly names: readonly string[];
  readonly value: OptionDeclaration["value"];
  readonly forms: OptionDeclaration["forms"];
  readonly action: CompiledTransitionAction;
}

export interface CompiledPolicyProgram {
  readonly language: PolicyDocument["language"];
  readonly layer: PolicyDocument["layer"];
  readonly select: PolicyDocument["select"];
  readonly registers: PolicyDocument["registers"];
  readonly folds: PolicyDocument["folds"];
  readonly start: string;
  readonly states: Readonly<Record<string, CompiledState>>;
  /** Internal states model every short-option-cluster microstep as byte consumption. */
  readonly clusterStates: Readonly<Record<string, CompiledClusterState>>;
  readonly metrics: Readonly<{ readonly states: number; readonly transitions: number; readonly cases: number }>;
}

/** Lower ordered option declarations and acyclic case fragments into DCRM states. */
export function compilePolicyDocument(ast: PolicyDocument): CompiledPolicyProgram {
  const states: Record<string, CompiledState> = {};
  const clusterStates: Record<string, CompiledClusterState> = {};
  let transitions = 0;
  let cases = 0;

  for (const [stateName, state] of Object.entries(ast.states)) {
    const lowered: CompiledCase[] = [];
    // Declared machine-wide and state-local options always precede authored cases.
    for (const [optionName, option] of Object.entries(ast.options)) {
      if (option.availableIn !== "*" && !option.availableIn.includes(stateName)) continue;
      const action = transition(stateName, option.set, []);
      lowered.push(Object.freeze({ when: optionWhen(optionName), action, origin: `option:${optionName}` }));
      transitions++;
      if (option.forms.includes("cluster")) {
        const internalName = `$cluster:${stateName}:${optionName}`;
        const clusterAction = Object.freeze({ ...action, consume: "cluster-byte" as const, progress: 1 });
        clusterStates[internalName] = Object.freeze({
          state: stateName,
          option: optionName,
          names: option.names,
          value: option.value,
          forms: option.forms,
          action: clusterAction,
        });
        transitions++;
      }
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
    start: ast.start,
    states: Object.freeze(states),
    clusterStates: Object.freeze(clusterStates),
    metrics: Object.freeze({ states: Object.keys(states).length + Object.keys(clusterStates).length, transitions, cases }),
  });
  if (program.metrics.transitions > POLICY_DOCUMENT_LIMITS.transitions || program.metrics.cases > POLICY_DOCUMENT_LIMITS.expandedCases) {
    throw new TypeError("compiled policy exceeds fixed transition or case limits");
  }
  assertCompiledProgress(program);
  return program;
}

function lowerCase(policyCase: PolicyCase, origin: CompiledCase["origin"]): CompiledCase {
  return Object.freeze({
    when: policyCase.when,
    action: policyCase.action.kind === "terminal" ? policyCase.action : transition(policyCase.action.next, policyCase.action.set, policyCase.action.fold),
    origin,
  });
}

function transition(next: string, set: Readonly<Record<string, Expression>>, fold: readonly string[]): CompiledTransitionAction {
  return Object.freeze({ kind: "transition", consume: "word", progress: 1, next, set, fold });
}

function optionWhen(name: string): CompiledOptionPredicate {
  return Object.freeze({ kind: "option", option: name });
}

function expandFragment(ast: PolicyDocument, name: string, stack: readonly string[] = []): readonly { readonly policyCase: PolicyCase; readonly origin: string }[] {
  if (stack.includes(name)) throw new TypeError(`cannot compile cyclic fragment ${name}`);
  const fragment = ast.fragments[name];
  if (!fragment) throw new TypeError(`cannot compile unknown fragment ${name}`);
  return Object.freeze([
    ...fragment.uses.flatMap((used) => expandFragment(ast, used, [...stack, name])),
    ...fragment.cases.map((policyCase) => Object.freeze({ policyCase, origin: name })),
  ]);
}

function assertCompiledProgress(program: CompiledPolicyProgram): void {
  for (const [stateName, state] of Object.entries(program.states)) {
    for (const [index, entry] of state.cases.entries()) {
      if (entry.action.kind === "transition" && (entry.action.progress < 1 || (entry.action.consume !== "word" && entry.action.consume !== "cluster-byte"))) {
        throw new TypeError(`compiled transition ${stateName}.cases[${index}] does not decrease input progress`);
      }
    }
  }
  for (const [name, state] of Object.entries(program.clusterStates)) {
    if (state.action.consume !== "cluster-byte" || state.action.progress < 1) {
      throw new TypeError(`compiled cluster state ${name} does not consume a byte`);
    }
  }
}
