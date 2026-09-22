import {
  POLICY_LANGUAGE_V1,
  type Action,
  type AuditValue,
  type Expression,
  type ExpressionType,
  type FoldDeclaration,
  type FragmentDeclaration,
  type OptionDeclaration,
  type PolicyCase,
  type PolicyDocument,
  type RegisterDeclaration,
  type Selector,
  type StateDeclaration,
  type TemplatePart,
  type TerminalAction,
} from "./ast.js";
import { builtinDefinition, type BuiltinValueType } from "./builtins.js";

export { POLICY_LANGUAGE_V1 } from "./ast.js";

export const POLICY_DOCUMENT_LIMITS = Object.freeze({
  bytes: 256 * 1024,
  states: 128,
  registers: 64,
  folds: 32,
  options: 64,
  selectors: 256,
  optionNames: 16,
  fragments: 64,
  casesPerState: 128,
  transitions: 4_096,
  nodes: 32_768,
  literals: 16_384,
  templateParts: 4_096,
  regexBytes: 8_192,
  expandedCases: 4_096,
});

export class PolicyDocumentValidationError extends TypeError {
  constructor(readonly pointer: string, message: string) {
    super(`${pointer}: ${message}`);
    this.name = "PolicyDocumentValidationError";
  }
}

interface ParseContext {
  readonly metrics: MutableMetrics;
  readonly instrumentation: ValidationInstrumentation;
}

/** Test-only hooks for measuring validator work without exposing domain data. */
export interface ValidationInstrumentation {
  readonly onEnumDomainComparison?: () => void;
}

interface MutableMetrics {
  nodes: number;
  validationWork: number;
  enumDomainChecks: number;
  enumDomainComparisons: number;
  selectors: number;
  states: number;
  transitions: number;
  compiledCases: number;
  literals: number;
  templateParts: number;
  regexBytes: number;
}

/** Parse either JSON text or an already-decoded JSON value into the validated v1 AST. */
export function parsePolicyDocument(json: string | unknown): PolicyDocument {
  const value = typeof json === "string" ? parseJsonWithoutDuplicateKeys(json) : json;
  return validatePolicyDocument(value);
}

/** Strict handwritten schema, type, and finite-progress validation for v1. */
export function validatePolicyDocument(value: unknown, instrumentation: ValidationInstrumentation = {}): PolicyDocument {
  const context: ParseContext = { metrics: { nodes: 0, validationWork: 0, enumDomainChecks: 0, enumDomainComparisons: 0, selectors: 0, states: 0, transitions: 0, compiledCases: 0, literals: 0, templateParts: 0, regexBytes: 0 }, instrumentation };
  const root = record(value, "$");
  exactKeys(root, ["language", "layer", "select", "registers", "folds", "options", "fragments", "start", "states"], ["registers", "folds", "options", "fragments"], "$");
  if (root.language !== POLICY_LANGUAGE_V1) fail("$.language", `language must be exactly ${POLICY_LANGUAGE_V1}`);
  if (root.layer !== "guard" && root.layer !== "permission") fail("$.layer", "layer must be guard or permission");

  const selectValues = array(root.select, "$.select", POLICY_DOCUMENT_LIMITS.selectors);
  const select = selectValues.map((entry, index) => parseSelector(entry, `$.select[${index}]`));
  context.metrics.selectors = select.length;
  if (select.length === 0) fail("$.select", "select must contain at least one selector");
  const registers = parseNamed(root.registers ?? {}, "$.registers", POLICY_DOCUMENT_LIMITS.registers, parseRegister);
  const folds = parseNamed(root.folds ?? {}, "$.folds", POLICY_DOCUMENT_LIMITS.folds, parseFold);
  const options = parseNamed(root.options ?? {}, "$.options", POLICY_DOCUMENT_LIMITS.options, parseOption);
  const fragments = parseNamed(root.fragments ?? {}, "$.fragments", POLICY_DOCUMENT_LIMITS.fragments, parseFragment);
  const states = parseNamed(root.states, "$.states", POLICY_DOCUMENT_LIMITS.states, parseState);
  context.metrics.states = Object.keys(states).length;
  if (context.metrics.states === 0) fail("$.states", "at least one state is required");
  if (typeof root.start !== "string" || !hasOwn(states, root.start)) fail("$.start", "start must name a declared state");

  const names = {
    states: new Set(Object.keys(states)),
    registers: new Map(Object.entries(registers).map(([name, declaration]) => [name, registerType(declaration)])),
    registerDeclarations: registers,
    folds: new Map(Object.entries(folds).map(([name, declaration]) => [name, foldResultType(declaration)])),
    foldDeclarations: folds,
    enumDomains: canonicalEnumDomains(registers),
    metrics: context.metrics,
    instrumentation: context.instrumentation,
  };
  const optionIndex = validateOptions(options, names, context);
  validateFolds(folds, names, context);
  const fragmentsPlan = validateFragments(fragments, root.layer, names, context);
  validateStates(states, fragments, fragmentsPlan, optionIndex, root.layer, names, context);
  measureDocument({ select, registers, folds, options, fragments, states }, context.metrics);
  assertMetrics(context.metrics, "$");

  return deepFreeze({
    language: POLICY_LANGUAGE_V1,
    layer: root.layer,
    select,
    registers,
    folds,
    options,
    fragments,
    start: root.start,
    states,
    metrics: Object.freeze({ ...context.metrics }),
  }) as PolicyDocument;
}

function parseSelector(value: unknown, pointer: string): Selector {
  const candidate = record(value, pointer);
  if (hasOwn(candidate, "kind")) {
    if (candidate.kind === "invocation") {
      exactKeys(candidate, ["kind"], [], pointer);
      return { kind: "invocation" };
    }
    if (candidate.kind === "execution-gap") {
      exactKeys(candidate, ["kind", "reason"], ["reason"], pointer);
      if (candidate.reason !== undefined && typeof candidate.reason !== "string") fail(`${pointer}.reason`, "reason must be a string");
      return candidate.reason === undefined ? { kind: "execution-gap" } : { kind: "execution-gap", reason: candidate.reason };
    }
    fail(`${pointer}.kind`, "unknown selector kind");
  }
  exactKeys(candidate, ["executable"], [], pointer);
  const executable = record(candidate.executable, `${pointer}.executable`);
  exactKeys(executable, ["projection", "equals"], [], `${pointer}.executable`);
  if (!isOneOf(executable.projection, ["basename", "selected-path", "canonical-target", "chain-contains"])) {
    fail(`${pointer}.executable.projection`, "projection must be an exact executable projection");
  }
  if (typeof executable.equals !== "string") fail(`${pointer}.executable.equals`, "equals must be a string");
  return { executable: { projection: executable.projection as Selector extends { readonly executable: infer E } ? E extends { readonly projection: infer P } ? P : never : never, equals: executable.equals } };
}

function parseRegister(value: unknown, pointer: string): RegisterDeclaration {
  const candidate = record(value, pointer);
  if (candidate.type === "bool") {
    exactKeys(candidate, ["type", "initial"], [], pointer);
    if (typeof candidate.initial !== "boolean") fail(`${pointer}.initial`, "bool register initial must be boolean");
    return { type: "bool", initial: candidate.initial };
  }
  if (candidate.type === "enum") {
    exactKeys(candidate, ["type", "values", "initial"], [], pointer);
    const values = strings(candidate.values, `${pointer}.values`);
    if (values.length === 0 || new Set(values).size !== values.length) fail(`${pointer}.values`, "enum values must be a non-empty unique string list");
    if (typeof candidate.initial !== "string" || !values.includes(candidate.initial)) fail(`${pointer}.initial`, "enum initial must be a declared value");
    return { type: "enum", values, initial: candidate.initial };
  }
  if (candidate.type === "count") {
    exactKeys(candidate, ["type", "max", "initial"], [], pointer);
    if (!positiveInteger(candidate.max)) fail(`${pointer}.max`, "count max must be a positive safe integer");
    if (!nonNegativeInteger(candidate.initial) || candidate.initial > candidate.max) fail(`${pointer}.initial`, "count initial must be within its bound");
    return { type: "count", max: candidate.max, initial: candidate.initial };
  }
  if (candidate.type === "inputRef") {
    exactKeys(candidate, ["type", "initial"], [], pointer);
    if (candidate.initial !== null) fail(`${pointer}.initial`, "inputRef initial must be null");
    return { type: "inputRef", initial: null };
  }
  if (candidate.type === "tuple") {
    exactKeys(candidate, ["type", "items", "initial"], [], pointer);
    const items = array(candidate.items, `${pointer}.items`, POLICY_DOCUMENT_LIMITS.registers).map((item, index) => parseRegister(item, `${pointer}.items[${index}]`));
    const initial = array(candidate.initial, `${pointer}.initial`, POLICY_DOCUMENT_LIMITS.registers);
    if (items.length === 0 || items.length !== initial.length) fail(pointer, "tuple items and initial must have the same non-zero length");
    for (const [index, item] of items.entries()) validateLiteralForRegister(initial[index], item, `${pointer}.initial[${index}]`);
    return { type: "tuple", items, initial };
  }
  fail(`${pointer}.type`, "register type must be bool, enum, count, inputRef, or tuple");
}

function parseFold(value: unknown, pointer: string): FoldDeclaration {
  const candidate = record(value, pointer);
  exactKeys(candidate, ["collection", "operation", "when", "limit"], ["limit"], pointer);
  if (!isOneOf(candidate.collection, ["argv", "redirects", "assignments", "provenance", "environment"])) fail(`${pointer}.collection`, "collection must be a finite event collection");
  if (!isOneOf(candidate.operation, ["any", "all", "firstRef", "lastRef", "countUpTo"])) fail(`${pointer}.operation`, "unknown fold operation");
  if (candidate.operation === "countUpTo") {
    if (!positiveInteger(candidate.limit)) fail(`${pointer}.limit`, "countUpTo requires a positive literal limit");
  } else if (candidate.limit !== undefined) fail(`${pointer}.limit`, "only countUpTo accepts limit");
  return { collection: candidate.collection as FoldDeclaration["collection"], operation: candidate.operation as FoldDeclaration["operation"], when: parseExpression(candidate.when, `${pointer}.when`), ...(candidate.limit === undefined ? {} : { limit: candidate.limit }) };
}

function parseOption(value: unknown, pointer: string): OptionDeclaration {
  const candidate = record(value, pointer);
  exactKeys(candidate, ["names", "value", "forms", "availableIn", "set"], ["set"], pointer);
  const names = strings(candidate.names, `${pointer}.names`, POLICY_DOCUMENT_LIMITS.optionNames);
  if (names.length === 0 || new Set(names).size !== names.length || names.some((name) => !/^--?[A-Za-z0-9][A-Za-z0-9-]*$/.test(name))) {
    fail(`${pointer}.names`, "names must be unique exact short or long option names");
  }
  if (!isOneOf(candidate.value, ["absent", "required", "optional"])) fail(`${pointer}.value`, "value must be absent, required, or optional");
  const forms = strings(candidate.forms, `${pointer}.forms`, 4);
  if (new Set(forms).size !== forms.length || forms.some((form) => !isOneOf(form, ["separate", "attachedShort", "equalsLong", "cluster"]))) {
    fail(`${pointer}.forms`, "forms contains an unknown or duplicate option form");
  }
  if (candidate.value === "absent" && forms.length !== 0) fail(`${pointer}.forms`, "absent-value options cannot consume a value form");
  if (candidate.value !== "absent" && forms.length === 0) fail(`${pointer}.forms`, "value-taking options require one or more forms");
  if (forms.includes("attachedShort") || forms.includes("cluster")) {
    if (!names.some((name) => /^-[^-]$/.test(name))) fail(`${pointer}.forms`, "short forms require an exact one-byte short name");
  }
  if (forms.includes("equalsLong") && !names.some((name) => name.startsWith("--"))) fail(`${pointer}.forms`, "equalsLong requires a long name");
  const availableIn = candidate.availableIn === "*" ? "*" as const : strings(candidate.availableIn, `${pointer}.availableIn`, POLICY_DOCUMENT_LIMITS.states);
  if (availableIn !== "*" && (availableIn.length === 0 || new Set(availableIn).size !== availableIn.length)) fail(`${pointer}.availableIn`, "availableIn must be * or a non-empty unique state list");
  const set = parseExpressionRecord(candidate.set ?? {}, `${pointer}.set`);
  if (candidate.value === "absent" && Object.values(set).some(referencesOptionValue)) {
    fail(`${pointer}.set`, "absent-value options cannot reference option.value");
  }
  return { names, value: candidate.value as OptionDeclaration["value"], forms: forms as OptionDeclaration["forms"], availableIn, set };
}

function parseFragment(value: unknown, pointer: string): FragmentDeclaration {
  const candidate = record(value, pointer);
  exactKeys(candidate, ["uses", "cases"], ["uses"], pointer);
  const uses = candidate.uses === undefined ? [] : strings(candidate.uses, `${pointer}.uses`, POLICY_DOCUMENT_LIMITS.fragments);
  if (new Set(uses).size !== uses.length) fail(`${pointer}.uses`, "fragment uses must be unique");
  return { uses, cases: array(candidate.cases, `${pointer}.cases`, POLICY_DOCUMENT_LIMITS.expandedCases).map((entry, index) => parseCase(entry, `${pointer}.cases[${index}]`)) };
}

function parseState(value: unknown, pointer: string): StateDeclaration {
  const candidate = record(value, pointer);
  exactKeys(candidate, ["fragments", "cases", "default", "end"], ["fragments"], pointer);
  const fragments = candidate.fragments === undefined ? [] : strings(candidate.fragments, `${pointer}.fragments`, POLICY_DOCUMENT_LIMITS.fragments);
  if (new Set(fragments).size !== fragments.length) fail(`${pointer}.fragments`, "state fragments must be unique");
  const cases = array(candidate.cases, `${pointer}.cases`, POLICY_DOCUMENT_LIMITS.casesPerState).map((entry, index) => parseCase(entry, `${pointer}.cases[${index}]`));
  const defaultAction = parseAction(candidate.default, `${pointer}.default`);
  const endAction = parseAction(candidate.end, `${pointer}.end`);
  if (defaultAction.kind !== "terminal") fail(`${pointer}.default`, "default must be a terminal action");
  if (endAction.kind !== "terminal") fail(`${pointer}.end`, "end must be a terminal action");
  return { fragments, cases, default: defaultAction, end: endAction };
}

function parseCase(value: unknown, pointer: string): PolicyCase {
  const candidate = record(value, pointer);
  exactKeys(candidate, ["when", "action"], [], pointer);
  return { when: parseExpression(candidate.when, `${pointer}.when`), action: parseAction(candidate.action, `${pointer}.action`) };
}

function parseAction(value: unknown, pointer: string): Action {
  const candidate = record(value, pointer);
  if (hasOwn(candidate, "decision")) {
    exactKeys(candidate, ["decision", "reason", "suggestion", "audit"], ["reason", "suggestion", "audit"], pointer);
    if (!isOneOf(candidate.decision, ["allow", "deny", "defer", "ignore"])) fail(`${pointer}.decision`, "unknown terminal decision");
    if ((candidate.decision === "allow" || candidate.decision === "deny") && candidate.reason === undefined) fail(`${pointer}.reason`, `${candidate.decision} requires a reason template`);
    if ((candidate.decision === "defer" || candidate.decision === "ignore") && (candidate.reason !== undefined || candidate.suggestion !== undefined || candidate.audit !== undefined)) {
      fail(pointer, `${candidate.decision} terminal cannot include reason, suggestion, or audit`);
    }
    return {
      kind: "terminal",
      decision: candidate.decision as TerminalAction["decision"],
      ...(candidate.reason === undefined ? {} : { reason: parseTemplate(candidate.reason, `${pointer}.reason`) }),
      ...(candidate.suggestion === undefined ? {} : { suggestion: parseTemplate(candidate.suggestion, `${pointer}.suggestion`) }),
      ...(candidate.audit === undefined ? {} : { audit: parseAudit(candidate.audit, `${pointer}.audit`) }),
    };
  }
  exactKeys(candidate, ["consume", "next", "set", "fold"], ["set", "fold"], pointer);
  if (candidate.consume !== "word") fail(`${pointer}.consume`, "nonterminal transitions must consume exactly one forward word");
  if (typeof candidate.next !== "string") fail(`${pointer}.next`, "transition next must be a static state name");
  const fold = candidate.fold === undefined ? [] : strings(candidate.fold, `${pointer}.fold`);
  if (new Set(fold).size !== fold.length) fail(`${pointer}.fold`, "transition folds must be unique static names");
  return { kind: "transition", consume: "word", next: candidate.next, set: parseExpressionRecord(candidate.set ?? {}, `${pointer}.set`), fold };
}

function parseExpression(value: unknown, pointer: string): Expression {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value as null | string | boolean;
  if (typeof value === "number") {
    if (!nonNegativeInteger(value)) fail(pointer, "number literals must be non-negative safe integers");
    return value;
  }
  if (Array.isArray(value)) return strings(value, pointer, POLICY_DOCUMENT_LIMITS.nodes);
  const candidate = record(value, pointer);
  if (hasOwn(candidate, "ref")) {
    exactKeys(candidate, ["ref"], [], pointer);
    if (typeof candidate.ref !== "string") fail(`${pointer}.ref`, "ref must be a string");
    return { ref: candidate.ref };
  }
  if (hasOwn(candidate, "call")) {
    exactKeys(candidate, ["call", "args"], [], pointer);
    if (typeof candidate.call !== "string") fail(`${pointer}.call`, "call must name a builtin");
    return { call: candidate.call, args: array(candidate.args, `${pointer}.args`).map((argument, index) => parseExpression(argument, `${pointer}.args[${index}]`)) };
  }
  if (hasOwn(candidate, "all") || hasOwn(candidate, "any")) {
    const key = hasOwn(candidate, "all") ? "all" : "any";
    exactKeys(candidate, [key], [], pointer);
    const expressions = array(candidate[key], `${pointer}.${key}`, POLICY_DOCUMENT_LIMITS.nodes).map((entry, index) => parseExpression(entry, `${pointer}.${key}[${index}]`));
    return key === "all" ? { all: expressions } : { any: expressions };
  }
  if (hasOwn(candidate, "not")) {
    exactKeys(candidate, ["not"], [], pointer);
    return { not: parseExpression(candidate.not, `${pointer}.not`) };
  }
  fail(pointer, "expression must be a literal, ref, builtin call, all, any, or not");
}

function parseTemplate(value: unknown, pointer: string): readonly TemplatePart[] {
  const parts = array(value, pointer);
  if (parts.length > POLICY_DOCUMENT_LIMITS.templateParts) fail(pointer, "template exceeds fixed size limit");
  return parts.map((part, index) => {
    if (typeof part === "string") return part;
    const reference = record(part, `${pointer}[${index}]`);
    exactKeys(reference, ["ref"], [], `${pointer}[${index}]`);
    if (typeof reference.ref !== "string") fail(`${pointer}[${index}].ref`, "template ref must be a string");
    return { ref: reference.ref };
  });
}

function parseAudit(value: unknown, pointer: string): Readonly<Record<string, AuditValue>> {
  const candidate = record(value, pointer);
  if (Object.keys(candidate).length > POLICY_DOCUMENT_LIMITS.templateParts) fail(pointer, "audit object exceeds fixed member limit");
  const budget: AuditBudget = { remaining: POLICY_DOCUMENT_LIMITS.templateParts };
  return Object.fromEntries(Object.entries(candidate).map(([key, entry]) => [key, parseAuditValue(entry, `${pointer}.${key}`, 0, budget)]));
}

interface AuditBudget { remaining: number; }

function parseAuditValue(value: unknown, pointer: string, depth: number, budget: AuditBudget): AuditValue {
  if (depth > 16) fail(pointer, "audit nesting exceeds fixed limit");
  if (budget.remaining-- === 0) fail(pointer, "audit values exceed fixed template limit");
  if (value === null || typeof value === "string" || typeof value === "boolean") return value as null | string | boolean;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail(pointer, "audit number must be a safe integer");
    return value;
  }
  if (Array.isArray(value)) {
    if (value.length > budget.remaining) fail(pointer, "audit values exceed fixed template limit");
    return value.map((entry, index) => parseAuditValue(entry, `${pointer}[${index}]`, depth + 1, budget));
  }
  const candidate = record(value, pointer);
  if (hasOwn(candidate, "ref")) {
    exactKeys(candidate, ["ref"], [], pointer);
    if (typeof candidate.ref !== "string") fail(`${pointer}.ref`, "audit ref must be a string");
    return { ref: candidate.ref };
  }
  const entries = Object.entries(candidate);
  if (entries.length > budget.remaining) fail(pointer, "audit values exceed fixed template limit");
  return Object.fromEntries(entries.map(([key, entry]) => [key, parseAuditValue(entry, `${pointer}.${key}`, depth + 1, budget)]));
}

interface FragmentPlan {
  readonly cases: ReadonlyMap<string, number>;
  readonly transitions: ReadonlyMap<string, number>;
}

interface OptionIndex {
  readonly machineWide: number;
  readonly local: ReadonlyMap<string, number>;
}

/** Count every materialized use site, saturating before any compile-time expansion. */
function validateFragments(fragments: Readonly<Record<string, FragmentDeclaration>>, layer: string, names: Names, context: ParseContext): FragmentPlan {
  const cases = new Map<string, number>();
  const transitions = new Map<string, number>();
  const visiting = new Set<string>();
  const expand = (name: string, pointer: string): void => {
    if (cases.has(name)) return;
    const fragment = fragments[name];
    if (!fragment) fail(pointer, `unknown fragment ${name}`);
    if (visiting.has(name)) fail(pointer, `fragment expansion is cyclic at ${name}`);
    visiting.add(name);
    let caseCount = fragment.cases.length;
    let transitionCount = fragment.cases.filter((entry) => entry.action.kind === "transition").length;
    for (const [index, used] of fragment.uses.entries()) {
      expand(used, `${pointer}.uses[${index}]`);
      caseCount = saturatingAdd(caseCount, cases.get(used)!);
      transitionCount = saturatingAdd(transitionCount, transitions.get(used)!);
    }
    visiting.delete(name);
    if (caseCount > POLICY_DOCUMENT_LIMITS.expandedCases || transitionCount > POLICY_DOCUMENT_LIMITS.transitions) {
      fail(pointer, "expanded fragment exceeds fixed case or transition limit");
    }
    cases.set(name, caseCount);
    transitions.set(name, transitionCount);
  };
  for (const [name, fragment] of Object.entries(fragments)) {
    for (const [index, policyCase] of fragment.cases.entries()) {
      validateCase(policyCase, layer, names, `$.fragments.${name}.cases[${index}]`);
      context.metrics.nodes += countCaseNodes(policyCase, `$.fragments.${name}.cases[${index}]`);
      if (policyCase.action.kind === "transition") context.metrics.transitions++;
    }
    expand(name, `$.fragments.${name}`);
  }
  return { cases, transitions };
}

function validateOptions(options: Readonly<Record<string, OptionDeclaration>>, names: Names, context: ParseContext): OptionIndex {
  const optionNames = new Set<string>();
  let machineWide = 0;
  const local = new Map<string, number>();
  for (const [name, option] of Object.entries(options)) {
    for (const optionName of option.names) {
      if (optionNames.has(optionName)) fail(`$.options.${name}.names`, `option name ${optionName} is declared more than once`);
      optionNames.add(optionName);
    }
    if (option.availableIn === "*") machineWide++;
    else for (const state of option.availableIn) {
      if (!names.states.has(state)) fail(`$.options.${name}.availableIn`, `unknown state ${state}`);
      local.set(state, (local.get(state) ?? 0) + 1);
    }
    validateAssignments(option.set, names, `$.options.${name}.set`);
    context.metrics.transitions += 1;
    context.metrics.nodes++;
  }
  return { machineWide, local };
}

function validateFolds(folds: Readonly<Record<string, FoldDeclaration>>, names: Names, context: ParseContext): void {
  for (const [name, fold] of Object.entries(folds)) {
    const type = expressionType(fold.when, names, `$.folds.${name}.when`, true);
    if (type !== "bool") fail(`$.folds.${name}.when`, "fold predicate must be boolean and cannot invoke a fold");
    context.metrics.nodes++;
  }
}

function validateStates(states: Readonly<Record<string, StateDeclaration>>, fragments: Readonly<Record<string, FragmentDeclaration>>, fragmentsPlan: FragmentPlan, options: OptionIndex, layer: string, names: Names, context: ParseContext): void {
  let expandedCases = 0;
  let compiledTransitions = 0;
  for (const [stateName, state] of Object.entries(states)) {
    for (const fragment of state.fragments) if (!hasOwn(fragments, fragment)) fail(`$.states.${stateName}.fragments`, `unknown fragment ${fragment}`);
    for (const [index, policyCase] of state.cases.entries()) {
      validateCase(policyCase, layer, names, `$.states.${stateName}.cases[${index}]`);
      context.metrics.nodes += countCaseNodes(policyCase, `$.states.${stateName}.cases[${index}]`);
      if (policyCase.action.kind === "transition") context.metrics.transitions++;
      expandedCases++;
      if (policyCase.action.kind === "transition") compiledTransitions++;
    }
    for (const fragment of state.fragments) {
      expandedCases = saturatingAdd(expandedCases, fragmentsPlan.cases.get(fragment)!);
      compiledTransitions = saturatingAdd(compiledTransitions, fragmentsPlan.transitions.get(fragment)!);
    }
    const optionTransitions = options.machineWide + (options.local.get(stateName) ?? 0);
    expandedCases = saturatingAdd(expandedCases, optionTransitions);
    compiledTransitions = saturatingAdd(compiledTransitions, optionTransitions);
    validateTerminal(state.default, layer, names, `$.states.${stateName}.default`);
    validateTerminal(state.end, layer, names, `$.states.${stateName}.end`);
  }
  if (expandedCases > POLICY_DOCUMENT_LIMITS.expandedCases) fail("$.states", "expanded fragment cases exceed fixed limit");
  if (compiledTransitions > POLICY_DOCUMENT_LIMITS.transitions) fail("$.states", "compiled transition count exceeds fixed limit");
  context.metrics.compiledCases = expandedCases;
}

function validateCase(policyCase: PolicyCase, layer: string, names: Names, pointer: string): void {
  if (expressionType(policyCase.when, names, `${pointer}.when`) !== "bool") fail(`${pointer}.when`, "case condition must be boolean");
  if (policyCase.action.kind === "terminal") validateTerminal(policyCase.action, layer, names, `${pointer}.action`);
  else validateTransition(policyCase.action, names, `${pointer}.action`);
}

function validateTransition(action: Extract<Action, { readonly kind: "transition" }>, names: Names, pointer: string): void {
  if (!names.states.has(action.next)) fail(`${pointer}.next`, `unknown state ${action.next}`);
  if (action.consume !== "word") fail(`${pointer}.consume`, "compiled transition cannot be non-consuming");
  for (const fold of action.fold) if (!names.folds.has(fold)) fail(`${pointer}.fold`, `unknown fold ${fold}`);
  validateAssignments(action.set, names, `${pointer}.set`);
}

function validateTerminal(action: TerminalAction, layer: string, names: Names, pointer: string): void {
  if (layer === "guard" && action.decision === "allow") fail(`${pointer}.decision`, "guard policies cannot allow");
  for (const [kind, template] of [["reason", action.reason], ["suggestion", action.suggestion]] as const) {
    for (const [index, part] of (template ?? []).entries()) if (typeof part !== "string") expressionType(part, names, `${pointer}.${kind}[${index}]`);
  }
  if (action.audit) validateAuditReferences(action.audit, names, `${pointer}.audit`);
}

function validateAuditReferences(value: AuditValue, names: Names, pointer: string): void {
  if (Array.isArray(value)) return value.forEach((entry, index) => validateAuditReferences(entry, names, `${pointer}[${index}]`));
  if (value && typeof value === "object") {
    if (hasOwn(value, "ref")) {
      expressionType(value as Expression, names, pointer);
      return;
    }
    for (const [key, entry] of Object.entries(value)) validateAuditReferences(entry, names, `${pointer}.${key}`);
  }
}

function validateAssignments(assignments: Readonly<Record<string, Expression>>, names: Names, pointer: string): void {
  for (const [name, expression] of Object.entries(assignments)) {
    const target = names.registers.get(name);
    if (!target) fail(`${pointer}.${name}`, `unknown register ${name}`);
    const declaration = names.registerDeclarations![name]!;
    const source = expressionType(expression, names, `${pointer}.${name}`);
    if (!assignable(source, target)) fail(`${pointer}.${name}`, `cannot assign ${source} to ${target}`);
    if (declaration.type === "enum" && typeof expression === "string") {
      if (!declaration.values.includes(expression)) fail(`${pointer}.${name}`, "enum assignment must be a declared value");
    } else if (declaration.type === "enum" && !sameEnumDomain(expression, name, names)) {
      fail(`${pointer}.${name}`, "enum assignment must be a member literal or a register with the same finite domain");
    }
    if (declaration.type === "count") {
      const bound = countBound(expression, names);
      if (bound === undefined || bound > declaration.max) fail(`${pointer}.${name}`, "count assignment must retain a bound no greater than the target cap");
    }
  }
}

interface Names {
  readonly states: Set<string>;
  readonly registers: Map<string, ExpressionType>;
  readonly registerDeclarations: Readonly<Record<string, RegisterDeclaration>>;
  readonly folds: Map<string, ExpressionType>;
  readonly foldDeclarations: Readonly<Record<string, FoldDeclaration>>;
  readonly enumDomains: ReadonlyMap<string, EnumDomain>;
  readonly metrics: MutableMetrics;
  readonly instrumentation: ValidationInstrumentation;
}

interface EnumDomain { readonly key: string; }

function canonicalEnumDomains(registers: Readonly<Record<string, RegisterDeclaration>>): ReadonlyMap<string, EnumDomain> {
  const canonical = new Map<string, EnumDomain>();
  const result = new Map<string, EnumDomain>();
  for (const [name, declaration] of Object.entries(registers)) {
    if (declaration.type !== "enum") continue;
    // JSON encoding makes every finite ordered string domain unambiguous.
    const key = JSON.stringify(declaration.values);
    const domain = canonical.get(key) ?? Object.freeze({ key });
    canonical.set(key, domain);
    result.set(name, domain);
  }
  return result;
}

function sameEnumDomain(expression: Expression, target: string, names: Names): boolean {
  names.metrics.enumDomainChecks++;
  if (expression === null || typeof expression !== "object" || Array.isArray(expression) || !hasOwn(expression, "ref")) return false;
  const source = (expression as { readonly ref: string }).ref;
  return compareEnumDomains(names.enumDomains.get(source), names.enumDomains.get(target), names);
}

/** The only enum-domain equality path; keep the operation observable in scale tests. */
function compareEnumDomains(source: EnumDomain | undefined, target: EnumDomain | undefined, names: Names): boolean {
  names.metrics.enumDomainComparisons++;
  names.instrumentation.onEnumDomainComparison?.();
  return source === target;
}

function countBound(expression: Expression, names: Names): number | undefined {
  if (typeof expression === "number") return expression;
  if (expression === null || typeof expression !== "object" || Array.isArray(expression)) return undefined;
  if (hasOwn(expression, "ref")) {
    const reference = (expression as { readonly ref: string }).ref;
    const register = names.registerDeclarations[reference];
    if (register?.type === "count") return register.max;
    const fold = reference.startsWith("fold.") ? names.foldDeclarations[reference.slice("fold.".length)] : undefined;
    return fold?.operation === "countUpTo" ? fold.limit : undefined;
  }
  if (hasOwn(expression, "call")) {
    const call = expression as { readonly call: string; readonly args: readonly Expression[] };
    return call.call === "parseBoundedInt" && typeof call.args[1] === "number" ? call.args[1] : undefined;
  }
  return undefined;
}

function expressionType(expression: Expression, names: Names, pointer: string, inFold = false): ExpressionType {
  if (typeof expression === "boolean") return "bool";
  if (typeof expression === "string") return "string";
  if (typeof expression === "number") return "count";
  if (expression === null) return "input-ref";
  if (Array.isArray(expression)) return "string-set";
  const object = expression as Exclude<Expression, string | number | boolean | null | readonly string[]>;
  if (hasOwn(object, "ref")) return referenceType((object as { readonly ref: string }).ref, names, pointer, inFold);
  if (hasOwn(object, "all") || hasOwn(object, "any")) {
    const expressions = hasOwn(object, "all") ? (object as { readonly all: readonly Expression[] }).all : (object as { readonly any: readonly Expression[] }).any;
    for (const [index, entry] of expressions.entries()) if (expressionType(entry, names, `${pointer}[${index}]`, inFold) !== "bool") fail(`${pointer}[${index}]`, "boolean combinators require boolean operands");
    return "bool";
  }
  if (hasOwn(object, "not")) {
    if (expressionType((object as { readonly not: Expression }).not, names, `${pointer}.not`, inFold) !== "bool") fail(`${pointer}.not`, "not requires a boolean operand");
    return "bool";
  }
  const call = object as { readonly call: string; readonly args: readonly Expression[] };
  const builtin = builtinDefinition(call.call);
  if (!builtin) fail(`${pointer}.call`, `unknown v1 builtin ${call.call}`);
  if (builtin.args.length !== call.args.length) fail(`${pointer}.args`, `${call.call} expects ${builtin.args.length} arguments`);
  for (const [index, expected] of builtin.args.entries()) {
    const actual = expressionType(call.args[index]!, names, `${pointer}.args[${index}]`, inFold);
    if (!assignable(actual, expected)) fail(`${pointer}.args[${index}]`, `${call.call} expects ${expected}, got ${actual}`);
  }
  if (call.call === "linearRegex") validateLinearRegex(call.args[1], `${pointer}.args[1]`);
  return builtin.result;
}

function referenceType(reference: string, names: Names, pointer: string, inFold: boolean): ExpressionType {
  if (reference === "word" || reference === "option.value" || reference === "event.executable" || reference === "fold.item") return "stringish";
  if (reference === "event.kind" || reference === "event.gap.reason") return "string";
  const register = names.registers.get(reference);
  if (register) return register;
  if (reference.startsWith("fold.")) {
    if (inFold) fail(pointer, "fold predicates cannot invoke or depend on a fold result");
    const fold = names.folds.get(reference.slice("fold.".length));
    if (fold) return fold;
  }
  fail(pointer, `unknown reference ${reference}`);
}

function validateLinearRegex(expression: Expression | undefined, pointer: string): void {
  if (typeof expression !== "string") fail(pointer, "linearRegex pattern must be a literal string");
  if (expression.length > POLICY_DOCUMENT_LIMITS.regexBytes) fail(pointer, "linearRegex pattern exceeds fixed limit");
  let index = 0;
  if (expression[index] === "^") index++;
  while (index < expression.length) {
    const character = expression[index]!;
    if (character === "$") {
      if (index !== expression.length - 1) fail(pointer, "linearRegex end anchor is permitted only at the end");
      return;
    }
    if (character === ".") {
      index++;
      continue;
    }
    if (character === "[") {
      index = validateRegexClass(expression, index, pointer);
      continue;
    }
    if (character === "\\") {
      index = validateRegexEscape(expression, index, pointer);
      continue;
    }
    if ("^$]()*+?{|}".includes(character)) {
      fail(pointer, "linearRegex permits only literal bytes, anchors, dot, character classes, and escaped literals");
    }
    index++;
  }
}

function validateRegexClass(pattern: string, start: number, pointer: string): number {
  let index = start + 1;
  if (pattern[index] === "^") index++;
  const contentStart = index;
  while (index < pattern.length && pattern[index] !== "]") {
    if (pattern[index] === "\\") index = validateRegexEscape(pattern, index, pointer);
    else {
      const character = pattern[index]!;
      if ("[() *+?{|}".replace(" ", "").includes(character)) fail(pointer, "linearRegex character class contains an unsupported metacharacter");
      index++;
    }
  }
  if (index === contentStart || pattern[index] !== "]") fail(pointer, "linearRegex character class must be non-empty and terminated");
  return index + 1;
}

function validateRegexEscape(pattern: string, index: number, pointer: string): number {
  const escaped = pattern[index + 1];
  if (escaped === undefined || !"\\.^$[]-".includes(escaped)) fail(pointer, "linearRegex escape is not in the restricted grammar");
  return index + 2;
}

function registerType(declaration: RegisterDeclaration): ExpressionType {
  return declaration.type === "bool" ? "bool" : declaration.type === "count" ? "count" : declaration.type === "enum" ? "string" : declaration.type === "inputRef" ? "input-ref" : "tuple";
}

function foldResultType(fold: FoldDeclaration): ExpressionType {
  return fold.operation === "any" || fold.operation === "all" ? "bool" : fold.operation === "countUpTo" ? "count" : "input-ref";
}

function assignable(actual: ExpressionType, expected: BuiltinValueType | ExpressionType): boolean {
  if (actual === expected || expected === "json") return true;
  if (expected === "stringish") return actual === "string" || actual === "stringish" || actual === "input-ref";
  if (expected === "input-ref") return actual === "input-ref" || actual === "stringish";
  if (expected === "string") return actual === "string";
  return false;
}

function countCaseNodes(policyCase: PolicyCase, pointer: string): number {
  void pointer;
  return 1 + countExpressionNodes(policyCase.when) + (policyCase.action.kind === "transition" ? Object.keys(policyCase.action.set).length : 0);
}

function countExpressionNodes(expression: Expression): number {
  if (expression === null || typeof expression !== "object") return 1;
  if (Array.isArray(expression)) return 1 + expression.length;
  const object = expression as Exclude<Expression, string | number | boolean | null | readonly string[]>;
  if (hasOwn(object, "call")) return 1 + (object as { readonly args: readonly Expression[] }).args.reduce<number>((total, entry) => total + countExpressionNodes(entry), 0);
  if (hasOwn(object, "all")) return 1 + (object as { readonly all: readonly Expression[] }).all.reduce<number>((total, entry) => total + countExpressionNodes(entry), 0);
  if (hasOwn(object, "any")) return 1 + (object as { readonly any: readonly Expression[] }).any.reduce<number>((total, entry) => total + countExpressionNodes(entry), 0);
  return hasOwn(object, "not") ? 1 + countExpressionNodes((object as { readonly not: Expression }).not) : 1;
}

function assertMetrics(metrics: MutableMetrics, pointer: string): void {
  if (metrics.selectors > POLICY_DOCUMENT_LIMITS.selectors) fail(pointer, "selector count exceeds fixed limit");
  if (metrics.transitions > POLICY_DOCUMENT_LIMITS.transitions) fail(pointer, "transition count exceeds fixed limit");
  if (metrics.nodes > POLICY_DOCUMENT_LIMITS.nodes) fail(pointer, "node count exceeds fixed limit");
  if (metrics.literals > POLICY_DOCUMENT_LIMITS.literals) fail(pointer, "literal table exceeds fixed limit");
  if (metrics.templateParts > POLICY_DOCUMENT_LIMITS.templateParts) fail(pointer, "template exceeds fixed limit");
  if (metrics.regexBytes > POLICY_DOCUMENT_LIMITS.regexBytes) fail(pointer, "regex program exceeds fixed limit");
}

/** Count every statically allocated expression/output node without evaluating it. */
function measureDocument(document: Pick<PolicyDocument, "select" | "registers" | "folds" | "options" | "fragments" | "states">, metrics: MutableMetrics): void {
  const measureExpression = (expression: Expression): void => {
    metrics.nodes++;
    if (typeof expression === "string") {
      metrics.literals += new TextEncoder().encode(expression).length;
      return;
    }
    if (expression === null || typeof expression !== "object") return;
    if (Array.isArray(expression)) {
      metrics.nodes += expression.length;
      for (const entry of expression) metrics.literals += new TextEncoder().encode(entry).length;
      return;
    }
    const object = expression as Exclude<Expression, string | number | boolean | null | readonly string[]>;
    if (hasOwn(object, "call")) {
      const call = object as { readonly call: string; readonly args: readonly Expression[] };
      if (call.call === "linearRegex" && typeof call.args[1] === "string") metrics.regexBytes += new TextEncoder().encode(call.args[1]).length;
      for (const argument of call.args) measureExpression(argument);
      return;
    }
    if (hasOwn(object, "all")) for (const entry of (object as { readonly all: readonly Expression[] }).all) measureExpression(entry);
    if (hasOwn(object, "any")) for (const entry of (object as { readonly any: readonly Expression[] }).any) measureExpression(entry);
    if (hasOwn(object, "not")) measureExpression((object as { readonly not: Expression }).not);
  };
  const measureAudit = (value: AuditValue): void => {
    metrics.nodes++;
    if (typeof value === "string") metrics.literals += new TextEncoder().encode(value).length;
    else if (Array.isArray(value)) value.forEach(measureAudit);
    else if (value && typeof value === "object" && !hasOwn(value, "ref")) Object.values(value).forEach(measureAudit);
  };
  const measureTerminal = (action: TerminalAction): void => {
    metrics.nodes++;
    for (const template of [action.reason, action.suggestion]) {
      if (!template) continue;
      metrics.templateParts += template.length;
      for (const part of template) if (typeof part === "string") metrics.literals += new TextEncoder().encode(part).length;
    }
    if (action.audit) Object.values(action.audit).forEach(measureAudit);
  };
  const measureCase = (policyCase: PolicyCase): void => {
    metrics.nodes++;
    measureExpression(policyCase.when);
    if (policyCase.action.kind === "terminal") measureTerminal(policyCase.action);
    else Object.values(policyCase.action.set).forEach(measureExpression);
  };
  for (const declaration of Object.values(document.registers)) {
    metrics.nodes++;
    if (declaration.type === "enum") declaration.values.forEach((value) => { metrics.literals += new TextEncoder().encode(value).length; });
  }
  for (const selector of document.select) {
    metrics.nodes++;
    if ("reason" in selector && selector.reason) metrics.literals += new TextEncoder().encode(selector.reason).length;
    if ("executable" in selector) metrics.literals += new TextEncoder().encode(selector.executable.equals).length;
  }
  for (const fold of Object.values(document.folds)) measureExpression(fold.when);
  for (const option of Object.values(document.options)) {
    metrics.nodes += option.names.length + option.forms.length + (option.availableIn === "*" ? 1 : option.availableIn.length);
    option.names.forEach((name) => { metrics.literals += new TextEncoder().encode(name).length; });
    Object.values(option.set).forEach(measureExpression);
  }
  for (const fragment of Object.values(document.fragments)) fragment.cases.forEach(measureCase);
  for (const state of Object.values(document.states)) {
    metrics.nodes++;
    state.cases.forEach(measureCase);
    measureTerminal(state.default);
    measureTerminal(state.end);
  }
  metrics.validationWork = metrics.nodes + metrics.selectors + Object.values(document.options)
    .reduce((total, option) => total + (option.availableIn === "*" ? 1 : option.availableIn.length), 0)
    + Object.values(document.fragments).reduce((total, fragment) => total + fragment.uses.length, 0)
    + metrics.enumDomainComparisons;
}

function parseNamed<T>(value: unknown, pointer: string, limit: number, parser: (value: unknown, pointer: string) => T): Readonly<Record<string, T>> {
  const candidate = record(value, pointer);
  const entries = Object.entries(candidate);
  if (entries.length > limit) fail(pointer, `contains more than ${limit} declarations`);
  const result: Record<string, T> = {};
  for (const [name, entry] of entries) {
    if (!identifier(name)) fail(`${pointer}.${name}`, "declaration name must be an ASCII identifier");
    result[name] = parser(entry, `${pointer}.${name}`);
  }
  return result;
}

function parseExpressionRecord(value: unknown, pointer: string): Readonly<Record<string, Expression>> {
  const entries = Object.entries(record(value, pointer));
  if (entries.length > POLICY_DOCUMENT_LIMITS.registers) fail(pointer, "assignment object exceeds fixed register limit");
  return Object.fromEntries(entries.map(([name, entry]) => [name, parseExpression(entry, `${pointer}.${name}`)]));
}

function referencesOptionValue(expression: Expression): boolean {
  if (expression === null || typeof expression !== "object") return false;
  if (Array.isArray(expression)) return false;
  const object = expression as Exclude<Expression, string | number | boolean | null | readonly string[]>;
  if (hasOwn(object, "ref")) return (object as { readonly ref: string }).ref === "option.value";
  if (hasOwn(object, "call")) return (object as { readonly args: readonly Expression[] }).args.some(referencesOptionValue);
  if (hasOwn(object, "all")) return (object as { readonly all: readonly Expression[] }).all.some(referencesOptionValue);
  if (hasOwn(object, "any")) return (object as { readonly any: readonly Expression[] }).any.some(referencesOptionValue);
  return hasOwn(object, "not") && referencesOptionValue((object as { readonly not: Expression }).not);
}

function validateLiteralForRegister(value: unknown, declaration: RegisterDeclaration, pointer: string): void {
  if (declaration.type === "bool" && typeof value !== "boolean") fail(pointer, "tuple bool initial must be boolean");
  if (declaration.type === "enum" && (typeof value !== "string" || !declaration.values.includes(value))) fail(pointer, "tuple enum initial must be declared");
  if (declaration.type === "count" && (!nonNegativeInteger(value) || value > declaration.max)) fail(pointer, "tuple count initial must be bounded");
  if (declaration.type === "inputRef" && value !== null) fail(pointer, "tuple inputRef initial must be null");
  if (declaration.type === "tuple") fail(pointer, "nested tuples are not supported");
}

function record(value: unknown, pointer: string): Record<string, any> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(pointer, "must be a JSON object");
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail(pointer, "must be a plain JSON object");
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") fail(pointer, "must not contain symbol keys");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) fail(`${pointer}.${key}`, "must contain only data properties");
  }
  return value as Record<string, any>;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], optional: readonly string[], pointer: string): void {
  const expected = new Set(allowed);
  for (const key of Object.keys(value)) if (!expected.has(key)) fail(pointer, `unknown key ${key}`);
  for (const key of allowed) if (!optional.includes(key) && !hasOwn(value, key)) fail(pointer, `missing required key ${key}`);
}

function array(value: unknown, pointer: string, limit: number = POLICY_DOCUMENT_LIMITS.nodes): unknown[] {
  if (!Array.isArray(value)) fail(pointer, "must be an array");
  if (value.length > limit) fail(pointer, `contains more than ${limit} entries`);
  return value;
}

function strings(value: unknown, pointer: string, limit: number = POLICY_DOCUMENT_LIMITS.nodes): string[] {
  return array(value, pointer, limit).map((entry, index) => {
    if (typeof entry !== "string") fail(`${pointer}[${index}]`, "must be a string");
    return entry;
  });
}

function hasOwn(value: object, key: string): boolean {
  return Object.hasOwn(value, key);
}

function isOneOf<T extends readonly string[]>(value: unknown, allowed: T): value is T[number] {
  return typeof value === "string" && allowed.includes(value);
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function positiveInteger(value: unknown): value is number {
  return nonNegativeInteger(value) && value > 0;
}

function identifier(value: string): boolean {
  return /^[A-Za-z][A-Za-z0-9_]*$/.test(value);
}

function fail(pointer: string, message: string): never {
  throw new PolicyDocumentValidationError(pointer, message);
}

function saturatingAdd(left: number, right: number): number {
  const limit = Math.max(POLICY_DOCUMENT_LIMITS.expandedCases, POLICY_DOCUMENT_LIMITS.transitions) + 1;
  return left > limit - right ? limit : left + right;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const entry of Object.values(value)) deepFreeze(entry, seen);
  return Object.freeze(value);
}

/** Detect duplicate object members before JSON.parse would discard one. */
function parseJsonWithoutDuplicateKeys(source: string): unknown {
  if (new TextEncoder().encode(source).length > POLICY_DOCUMENT_LIMITS.bytes) fail("$", "JSON source exceeds fixed byte limit");
  let index = 0;
  const whitespace = () => { while (/\s/.test(source[index] ?? "")) index++; };
  const quoted = (): string => {
    const start = index;
    if (source[index] !== '"') throw new SyntaxError("expected JSON string");
    index++;
    while (index < source.length) {
      if (source[index] === "\\") { index += 2; continue; }
      if (source[index++] === '"') return JSON.parse(source.slice(start, index));
    }
    throw new SyntaxError("unterminated JSON string");
  };
  const primitive = () => {
    const start = index;
    while (index < source.length && !/[\s,}\]]/.test(source[index]!)) index++;
    JSON.parse(source.slice(start, index));
  };
  const value = (): void => {
    whitespace();
    if (source[index] === "{") {
      index++; whitespace();
      const keys = new Set<string>();
      if (source[index] === "}") { index++; return; }
      while (true) {
        whitespace(); const key = quoted();
        if (keys.has(key)) fail("$", `duplicate JSON object key ${key}`);
        keys.add(key); whitespace();
        if (source[index++] !== ":") throw new SyntaxError("expected JSON colon");
        value(); whitespace();
        if (source[index] === "}") { index++; return; }
        if (source[index++] !== ",") throw new SyntaxError("expected JSON comma");
      }
    }
    if (source[index] === "[") {
      index++; whitespace();
      if (source[index] === "]") { index++; return; }
      while (true) {
        value(); whitespace();
        if (source[index] === "]") { index++; return; }
        if (source[index++] !== ",") throw new SyntaxError("expected JSON comma");
      }
    }
    if (source[index] === '"') { quoted(); return; }
    primitive();
  };
  try {
    value(); whitespace();
    if (index !== source.length) throw new SyntaxError("unexpected trailing JSON input");
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof PolicyDocumentValidationError) throw error;
    const detail = error instanceof Error ? error.message : "invalid JSON";
    fail("$", `invalid JSON: ${detail}`);
  }
}
