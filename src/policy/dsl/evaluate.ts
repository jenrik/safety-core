import type { BindingValue } from "../../bash/environment.js";
import type { ResolvedWord } from "../../bash/expand.js";
import type { BashPolicyEvent, BashPolicySelector, DslPolicyTraceStep, LoadedBashPolicy, PolicyDecision, PolicyDiagnosticPart, PolicySourceIdentity } from "../types.js";
import type { AuditValue, Expression, FoldDeclaration, RegisterDeclaration, TerminalAction } from "./ast.js";
import type { CompiledCase, CompiledOptionAction, CompiledPolicyProgram } from "./compile.js";

export interface DslMachineStep extends DslPolicyTraceStep {}

export interface DslEvaluation {
  readonly decision: PolicyDecision;
  readonly steps: readonly DslMachineStep[];
}

export interface DslLoadedBashPolicy extends LoadedBashPolicy {
  evaluateWithTrace(event: BashPolicyEvent): DslEvaluation;
}

type InputReference = { readonly word: ResolvedWord; readonly start?: number; readonly end?: number };
type RuntimeValue = unknown | InputReference | typeof UNKNOWN;
const UNKNOWN = Symbol("dsl-unknown");
const NORMAL_WORD = -1;
const OPTIONS_ENDED = -2;

/** Create a pure, one-event DCRM policy. Every call starts from its fixed initial configuration. */
export function createDslPolicy(program: CompiledPolicyProgram, source: string | PolicySourceIdentity): DslLoadedBashPolicy {
  const identity = typeof source === "string" ? Object.freeze({ canonicalPath: source }) : Object.freeze({ canonicalPath: source.canonicalPath });
  const selectors = Object.freeze(program.select.map(selectorForLoadedPolicy));
  const evaluateWithTrace = (event: BashPolicyEvent): DslEvaluation => evaluateProgram(program, event);
  return Object.freeze({
    source: identity,
    layer: program.layer,
    select: selectors,
    evaluate(event: BashPolicyEvent): PolicyDecision { return evaluateWithTrace(event).decision; },
    evaluateWithTrace,
  });
}

function evaluateProgram(program: CompiledPolicyProgram, event: BashPolicyEvent): DslEvaluation {
  if (!selects(program, event)) return frozenEvaluation({ kind: "ignore" }, []);

  const argv = event.kind === "invocation" ? event.argv : [];
  let state = program.start;
  let argvIndex = 0;
  let clusterByteIndex = NORMAL_WORD;
  let registers: Readonly<Record<string, RuntimeValue>> = initialRegisters(program.registers);
  const foldCache = new Map<string, RuntimeValue>();
  const steps: DslMachineStep[] = [];

  // Validation proves every non-terminal configuration consumes an argv word or cluster byte.
  while (true) {
    const activeWord = argv[argvIndex];
    const stateProgram = program.states[state];
    if (!stateProgram) throw new TypeError(`compiled DCRM state is missing: ${state}`);
    if (!activeWord) {
      const decision = terminalDecision(stateProgram.end, runtimeContext(event, undefined, undefined, registers, foldCache));
      steps.push(step(state, argvIndex, clusterByteIndex, `$.states.${state}.end`, `state:${state}`, "terminal", [], undefined, decision.kind));
      return frozenEvaluation(decision, steps);
    }

    if (clusterByteIndex === NORMAL_WORD && isKnown(activeWord) && activeWord.value === "--") {
      steps.push(step(state, argvIndex, OPTIONS_ENDED, "$.states", "argv:--", "end-options", []));
      argvIndex++;
      clusterByteIndex = OPTIONS_ENDED;
      continue;
    }

    const malformedOption = clusterByteIndex !== OPTIONS_ENDED && stateProgram.cases.some((entry) => entry.action.kind === "option"
      && matchOption(entry.action, activeWord, clusterByteIndex, argv[argvIndex + 1]) === undefined
      && optionSpellingMatches(entry.action, activeWord, clusterByteIndex));
    let matched = false;
    for (const entry of stateProgram.cases) {
      if (malformedOption && entry.action.kind !== "option") continue;
      const option = entry.action.kind === "option" ? matchOption(entry.action, activeWord, clusterByteIndex, argv[argvIndex + 1]) : undefined;
      const context = runtimeContext(event, activeWord, option?.value, registers, foldCache);
      const guard = isOptionPredicate(entry.when)
        ? option !== undefined && clusterByteIndex !== OPTIONS_ENDED
        : evaluateExpression(entry.when, context) === true;
      if (!guard) continue;

      matched = true;
      if (entry.action.kind === "terminal") {
        const decision = terminalDecision(entry.action, context);
        steps.push(step(state, argvIndex, clusterByteIndex, entry.source, entry.origin, "terminal", [], undefined, decision.kind));
        return frozenEvaluation(decision, steps);
      }

      const action = entry.action;
      const folds = computeFolds(program, action.fold, event, registers, foldCache);
      const updated = simultaneousUpdates(action.set, runtimeContext(event, activeWord, option?.value, registers, foldCache));
      registers = Object.freeze({ ...registers, ...updated });
      const progress = action.kind === "option"
        ? consumeOption(action, option!, activeWord, argvIndex, clusterByteIndex, argv)
        : { argvIndex: argvIndex + 1, clusterByteIndex: clusterByteIndex === OPTIONS_ENDED ? OPTIONS_ENDED : NORMAL_WORD };
      steps.push(step(state, argvIndex, clusterByteIndex, entry.source, entry.origin, action.kind, folds, action.next));
      state = action.next;
      argvIndex = progress.argvIndex;
      clusterByteIndex = progress.clusterByteIndex;
      break;
    }
    if (matched) continue;

    const decision = terminalDecision(stateProgram.default, runtimeContext(event, activeWord, undefined, registers, foldCache));
    steps.push(step(state, argvIndex, clusterByteIndex, `$.states.${state}.default`, `state:${state}`, "terminal", [], undefined, decision.kind));
    return frozenEvaluation(decision, steps);
  }
}

function selects(program: CompiledPolicyProgram, event: BashPolicyEvent): boolean {
  return program.select.every((selector) => {
    if ("kind" in selector) return event.kind === selector.kind && (selector.kind !== "execution-gap" || selector.reason === undefined || event.reason === selector.reason);
    if (event.kind !== "invocation") return false;
    const identity = event.executableIdentity;
    switch (selector.executable.projection) {
      case "basename": return identity.qualification !== "unknown" && identity.basename === selector.executable.equals;
      case "selected-path": return identity.qualification === "known" && identity.selectedPath === selector.executable.equals;
      case "canonical-target": return identity.qualification === "known" && identity.canonicalTarget === selector.executable.equals;
      case "chain-contains": return identity.qualification === "known" && identity.chain.includes(selector.executable.equals);
    }
  });
}

function selectorForLoadedPolicy(selector: CompiledPolicyProgram["select"][number]): BashPolicySelector {
  if ("kind" in selector) return Object.freeze(selector.reason === undefined ? { kind: selector.kind } : { kind: selector.kind, reason: selector.reason });
  const kind = selector.executable.projection === "basename" ? "executable-basename"
    : selector.executable.projection === "selected-path" ? "executable-selected-path"
      : selector.executable.projection === "canonical-target" ? "executable-canonical-target" : "executable-chain-contains";
  return Object.freeze({ kind, value: selector.executable.equals });
}

function initialRegisters(declarations: Readonly<Record<string, RegisterDeclaration>>): Readonly<Record<string, RuntimeValue>> {
  return Object.freeze(Object.fromEntries(Object.entries(declarations).map(([name, declaration]) => [name, initialRegister(declaration)])));
}

function initialRegister(declaration: RegisterDeclaration): RuntimeValue {
  if (declaration.type === "tuple") return declaration.initial;
  return declaration.initial;
}

interface RuntimeContext {
  readonly event: BashPolicyEvent;
  readonly word: ResolvedWord | undefined;
  readonly optionValue: InputReference | null | undefined;
  readonly registers: Readonly<Record<string, RuntimeValue>>;
  readonly folds: ReadonlyMap<string, RuntimeValue>;
  readonly foldItem?: RuntimeValue;
}

function runtimeContext(event: BashPolicyEvent, word: ResolvedWord | undefined, optionValue: InputReference | null | undefined, registers: Readonly<Record<string, RuntimeValue>>, folds: ReadonlyMap<string, RuntimeValue>, foldItem?: RuntimeValue): RuntimeContext {
  return { event, word, optionValue, registers, folds, foldItem };
}

function evaluateExpression(expression: Expression, context: RuntimeContext): RuntimeValue {
  if (expression === null || typeof expression === "string" || typeof expression === "number" || typeof expression === "boolean") return expression;
  if (Array.isArray(expression)) return expression;
  if ("ref" in expression) return reference(expression.ref, context);
  if ("call" in expression) return builtin(expression.call, expression.args.map((argument) => evaluateExpression(argument, context)), context);
  if ("all" in expression) {
    let unknown = false;
    for (const item of expression.all) {
      const value = evaluateExpression(item, context);
      if (value === false) return false;
      if (value !== true) unknown = true;
    }
    return unknown ? UNKNOWN : true;
  }
  if ("any" in expression) {
    let unknown = false;
    for (const item of expression.any) {
      const value = evaluateExpression(item, context);
      if (value === true) return true;
      if (value !== false) unknown = true;
    }
    return unknown ? UNKNOWN : false;
  }
  const value = evaluateExpression(expression.not, context);
  return value === true ? false : value === false ? true : UNKNOWN;
}

function reference(name: string, context: RuntimeContext): RuntimeValue {
  if (name === "word") return context.word === undefined ? UNKNOWN : inputReference(context.word);
  if (name === "option.value") return context.optionValue === undefined ? UNKNOWN : context.optionValue;
  if (name === "fold.item") return context.foldItem ?? UNKNOWN;
  if (name === "event.kind") return context.event.kind;
  if (name === "event.gap.reason") return context.event.kind === "execution-gap" ? context.event.reason : UNKNOWN;
  if (name === "event.executable") return context.event.kind === "invocation" && context.event.executable !== null ? inputReference(context.event.executable) : UNKNOWN;
  if (name.startsWith("fold.")) return context.folds.get(name.slice(5)) ?? UNKNOWN;
  return Object.hasOwn(context.registers, name) ? context.registers[name]! : UNKNOWN;
}

function simultaneousUpdates(assignments: Readonly<Record<string, Expression>>, context: RuntimeContext): Readonly<Record<string, RuntimeValue>> {
  return Object.freeze(Object.fromEntries(Object.entries(assignments).map(([name, expression]) => [name, evaluateExpression(expression, context)])));
}

function computeFolds(program: CompiledPolicyProgram, requested: readonly string[], event: BashPolicyEvent, registers: Readonly<Record<string, RuntimeValue>>, cache: Map<string, RuntimeValue>): readonly string[] {
  const evaluated: string[] = [];
  for (const name of requested) {
    if (cache.has(name)) continue;
    const declaration = program.folds[name];
    if (!declaration) throw new TypeError(`compiled DCRM fold is missing: ${name}`);
    cache.set(name, evaluateFold(declaration, event, registers, cache));
    evaluated.push(name);
  }
  return Object.freeze(evaluated);
}

function evaluateFold(declaration: FoldDeclaration, event: BashPolicyEvent, registers: Readonly<Record<string, RuntimeValue>>, cache: ReadonlyMap<string, RuntimeValue>): RuntimeValue {
  const values = foldCollection(declaration.collection, event);
  const predicate = (item: RuntimeValue) => evaluateExpression(declaration.when, runtimeContext(event, undefined, undefined, registers, cache, item));
  if (declaration.operation === "any") {
    let unknown = false;
    for (const value of values) { const result = predicate(value); if (result === true) return true; if (result !== false) unknown = true; }
    return unknown ? UNKNOWN : false;
  }
  if (declaration.operation === "all") {
    let unknown = false;
    for (const value of values) { const result = predicate(value); if (result === false) return false; if (result !== true) unknown = true; }
    return unknown ? UNKNOWN : true;
  }
  if (declaration.operation === "firstRef") {
    for (const value of values) if (predicate(value) === true) return value;
    return null;
  }
  if (declaration.operation === "lastRef") {
    let result: RuntimeValue = null;
    for (const value of values) if (predicate(value) === true) result = value;
    return result;
  }
  let count = 0;
  for (const value of values) if (predicate(value) === true && ++count >= declaration.limit!) return declaration.limit!;
  return count;
}

function foldCollection(collection: FoldDeclaration["collection"], event: BashPolicyEvent): readonly RuntimeValue[] {
  if (collection === "argv") return event.kind === "invocation" ? event.argv.map(inputReference) : [];
  if (collection === "redirects") return event.kind === "invocation" ? event.redirects : [];
  if (collection === "assignments") return event.kind === "invocation" ? Object.values(event.assignments) : [];
  if (collection === "provenance") return event.provenance.route;
  return Object.values(event.environment);
}

interface OptionMatch { readonly value?: InputReference | null; readonly consumes: "word" | "separate" | "cluster"; readonly nextClusterByteIndex?: number; }

function matchOption(action: CompiledOptionAction, word: ResolvedWord, clusterByteIndex: number, next: ResolvedWord | undefined): OptionMatch | undefined {
  if (!isKnown(word)) return undefined;
  const value = word.value;
  if (clusterByteIndex >= 0) {
    if ((action.value !== "absent" && !action.forms.includes("cluster")) || !value.startsWith("-") || value.startsWith("--")) return undefined;
    const name = `-${value[clusterByteIndex] ?? ""}`;
    if (!action.names.includes(name)) return undefined;
    const after = clusterByteIndex + 1;
    if (action.value === "absent") return { consumes: after < value.length ? "cluster" : "word", nextClusterByteIndex: after };
    if (after < value.length) return { consumes: "word", value: inputReference(word, after, Buffer.byteLength(value)) };
    return separateOptionValue(action, next);
  }
  for (const name of action.names) {
    if (value === name) {
      if (action.value === "absent") return { consumes: "word" };
      return separateOptionValue(action, next);
      continue;
    }
    if (action.forms.includes("attachedShort") && /^-[^-]$/.test(name) && value.startsWith(name) && value.length > name.length) {
      return { consumes: "word", value: inputReference(word, Buffer.byteLength(name), Buffer.byteLength(value)) };
    }
    if (action.forms.includes("equalsLong") && name.startsWith("--") && value.startsWith(`${name}=`)) {
      return { consumes: "word", value: inputReference(word, Buffer.byteLength(name) + 1, Buffer.byteLength(value)) };
    }
    if ((action.value === "absent" || action.forms.includes("cluster")) && /^-[^-]$/.test(name) && value.startsWith("-") && !value.startsWith("--") && value.length > 2 && value[1] === name[1]) {
      const after = 2;
      if (action.value === "absent") return { consumes: "cluster", nextClusterByteIndex: after };
      if (after < Buffer.byteLength(value)) return { consumes: "word", value: inputReference(word, after, Buffer.byteLength(value)) };
    }
  }
  return undefined;
}

function consumeOption(action: CompiledOptionAction, option: OptionMatch, word: ResolvedWord, argvIndex: number, clusterByteIndex: number, argv: readonly ResolvedWord[]): { readonly argvIndex: number; readonly clusterByteIndex: number } {
  if (option.consumes === "cluster") return { argvIndex, clusterByteIndex: option.nextClusterByteIndex ?? clusterByteIndex + 1 };
  if (option.consumes === "separate") return { argvIndex: argvIndex + 2, clusterByteIndex: NORMAL_WORD };
  return { argvIndex: argvIndex + 1, clusterByteIndex: NORMAL_WORD };
}

function separateOptionValue(action: CompiledOptionAction, next: ResolvedWord | undefined): OptionMatch | undefined {
  if (!action.forms.includes("separate")) return action.value === "optional" ? { consumes: "word", value: null } : undefined;
  if (action.value === "required") return next === undefined ? undefined : { consumes: "separate", value: inputReference(next) };
  return next !== undefined && !looksLikeOption(next) ? { consumes: "separate", value: inputReference(next) } : { consumes: "word", value: null };
}

function optionSpellingMatches(action: CompiledOptionAction, word: ResolvedWord, clusterByteIndex: number): boolean {
  if (!isKnown(word)) return false;
  if (clusterByteIndex >= 0) return word.value.startsWith("-") && !word.value.startsWith("--")
    && action.names.includes(`-${word.value[clusterByteIndex] ?? ""}`);
  return action.names.some((name) => word.value === name
    || /^-[^-]$/.test(name) && word.value.startsWith(name) && word.value.length > name.length
    || name.startsWith("--") && word.value.startsWith(`${name}=`));
}

function looksLikeOption(word: ResolvedWord): boolean { return isKnown(word) && word.value.startsWith("-") && word.value !== "-"; }

function terminalDecision(action: TerminalAction, context: RuntimeContext): PolicyDecision {
  if (action.decision === "ignore") return Object.freeze({ kind: "ignore" });
  if (action.decision === "defer") return Object.freeze({ kind: "defer" });
  const reason = template(action.reason ?? [], context);
  const audit = action.audit === undefined ? undefined : auditValue(action.audit, context) as Readonly<Record<string, unknown>>;
  const suggestion = action.suggestion === undefined ? undefined : template(action.suggestion, context);
  return Object.freeze({ kind: action.decision, reason, ...(suggestion === undefined ? {} : { suggestion }), ...(audit === undefined ? {} : { audit }) }) as PolicyDecision;
}

function template(parts: readonly (string | { readonly ref: string })[], context: RuntimeContext): readonly PolicyDiagnosticPart[] {
  return Object.freeze(parts.map((part) => typeof part === "string"
    ? Object.freeze({ kind: "literal" as const, value: part })
    : Object.freeze({ kind: "value" as const, value: materialize(reference(part.ref, context)) })));
}

function auditValue(value: AuditValue, context: RuntimeContext): unknown {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return Object.freeze(value.map((item) => auditValue(item, context)));
  if ("ref" in value) return materialize(reference(value.ref, context));
  return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, item]) => [key, auditValue(item, context)])));
}

function builtin(name: string, args: readonly RuntimeValue[], context: RuntimeContext): RuntimeValue {
  const strings = args.map(stringValue);
  if (requiresKnownOperands(name) && (args.some(isUnknown) || strings.some(isUnknown))) return UNKNOWN;
  switch (name) {
    case "equals": return strings[0] === strings[1];
    case "inStringSet": return isUnknown(strings[0]) ? UNKNOWN : Array.isArray(args[1]) && args[1].includes(strings[0] as string);
    case "asciiLower": return isUnknown(strings[0]) ? UNKNOWN : asciiCase(strings[0], false);
    case "asciiUpper": return isUnknown(strings[0]) ? UNKNOWN : asciiCase(strings[0], true);
    case "equalsAsciiCaseInsensitive": return asciiCase(strings[0] as string, false) === asciiCase(strings[1] as string, false);
    case "wordInAsciiCaseInsensitiveSet": return isUnknown(strings[0]) ? UNKNOWN : Array.isArray(args[1]) && args[1].some((value) => asciiCase(value, false) === asciiCase(strings[0] as string, false));
    case "startsWith": return (strings[0] as string).startsWith(strings[1] as string);
    case "endsWith": return (strings[0] as string).endsWith(strings[1] as string);
    case "includes": return (strings[0] as string).includes(strings[1] as string);
    case "basename": return isUnknown(strings[0]) ? UNKNOWN : (strings[0] as string).split("/").filter(Boolean).at(-1) ?? "";
    case "pathComponent": return isUnknown(strings[0]) ? UNKNOWN : (strings[0] as string).split("/").filter(Boolean)[args[1] as number] ?? "";
    case "splitComponent": return isUnknown(strings[0]) || isUnknown(strings[1]) ? UNKNOWN : (strings[0] as string).split(strings[1] as string)[args[2] as number] ?? "";
    case "parseBoundedInt": return isUnknown(strings[0]) ? UNKNOWN : Math.min(Number.isSafeInteger(Number(strings[0])) && /^\d+$/.test(strings[0] as string) ? Number(strings[0]) : 0, args[1] as number);
    case "boundedIntAtMost": return (args[0] as number) <= (args[1] as number);
    case "safeGlob": return isUnknown(strings[0]) || isUnknown(strings[1]) ? UNKNOWN : glob(strings[0] as string, strings[1] as string);
    case "linearRegex": return matchesLinearRegex(strings[0] as string, strings[1] as string);
    case "parseUrl": return isUnknown(strings[0]) ? UNKNOWN : parseUrl(strings[0] as string);
    case "urlHostEquals": return isUnknown(args[0]) || isUnknown(strings[1]) ? UNKNOWN : isUrl(args[0]) && args[0].host === asciiCase(strings[1] as string, false);
    case "parseRepository": return isUnknown(strings[0]) ? UNKNOWN : parseRepository(strings[0] as string);
    case "repositoryEquals": return isRepository(args[0]) && args[0].owner === strings[1] && args[0].repository === strings[2];
    case "normalizeKubernetesResource": return isUnknown(strings[0]) ? UNKNOWN : normalizeKubernetes(strings[0] as string);
    case "normalizeGitHubEndpoint": return isUnknown(strings[0]) ? UNKNOWN : normalizeEndpoint(strings[0] as string);
    case "environmentLookup": return environmentLookup(context.event, strings[0]);
    case "environmentIsPresent": return !isUnknown(args[0]) && isBinding(args[0]) && args[0].kind !== "unset";
    case "environmentIsKnown": return !isUnknown(args[0]) && isBinding(args[0]) && args[0].kind === "known";
    case "environmentIsUnknown": return isUnknown(args[0]) || (isBinding(args[0]) && args[0].kind === "unknown");
    case "environmentValueEquals": return isBinding(args[0]) && args[0].kind === "known" && args[0].value === strings[1];
    case "environmentIsExported": return typeof strings[0] === "string" && context.event.kind === "invocation" && context.event.exportedEnvironment?.[strings[0]] === true;
    case "missingEnvironmentMayBePresent": return context.event.missingBindings === "unknown";
    case "redirectHasInputPath": return isUnknown(strings[0]) ? UNKNOWN : context.event.kind === "invocation" && context.event.redirects.some((redirect) => redirect.target !== null && stringValue(inputReference(redirect.target)) === strings[0]);
    case "hasAssignment": return typeof strings[0] === "string" && context.event.kind === "invocation" && Object.hasOwn(context.event.assignments, strings[0]);
    case "hasProvenanceRoute": return typeof strings[0] === "string" && context.event.provenance.route.includes(strings[0]);
    case "isInPipeline": return context.event.inPipeline;
    case "processEffectIs": return strings[0] === context.event.processEffect;
    default: throw new TypeError(`unknown compiled DCRM builtin: ${name}`);
  }
}

function environmentLookup(event: BashPolicyEvent, name: string | typeof UNKNOWN): RuntimeValue {
  if (isUnknown(name)) return UNKNOWN;
  const value = event.environment[name];
  return value ?? (event.missingBindings === "unset" ? Object.freeze({ kind: "unset" as const }) : UNKNOWN);
}
function inputReference(word: ResolvedWord, start?: number, end?: number): InputReference { return Object.freeze({ word, ...(start === undefined ? {} : { start }), ...(end === undefined ? {} : { end }) }); }
function stringValue(value: RuntimeValue): string | typeof UNKNOWN {
  if (isUnknown(value)) return UNKNOWN;
  if (isInputReference(value)) {
    if (!isKnown(value.word)) return UNKNOWN;
    if (value.start === undefined || value.end === undefined) return value.word.value;
    return Buffer.from(value.word.value).subarray(value.start, value.end).toString();
  }
  return typeof value === "string" ? value : UNKNOWN;
}
function materialize(value: RuntimeValue): unknown { return isInputReference(value) ? (isKnown(value.word) ? stringValue(value) : value.word) : isUnknown(value) ? { kind: "unknown" } : value; }
function isKnown(word: ResolvedWord): word is Extract<ResolvedWord, { readonly kind: "known" }> { return word.kind === "known"; }
function isInputReference(value: unknown): value is InputReference { return typeof value === "object" && value !== null && "word" in value; }
function isUnknown(value: unknown): value is typeof UNKNOWN { return value === UNKNOWN; }
function isBinding(value: unknown): value is BindingValue { return typeof value === "object" && value !== null && "kind" in value && ["known", "unknown", "unset"].includes((value as { kind: string }).kind); }
function asciiCase(value: string, upper: boolean): string { return value.replace(/[A-Za-z]/g, (character) => upper ? character.toUpperCase() : character.toLowerCase()); }
function glob(value: string, pattern: string): boolean { const row = Array<boolean>(pattern.length + 1).fill(false); row[0] = true; for (let j = 1; j <= pattern.length; j++) row[j] = pattern[j - 1] === "*" && row[j - 1]!; for (const character of value) { let previous = row[0]!; row[0] = false; for (let j = 1; j <= pattern.length; j++) { const before = row[j]!; row[j] = pattern[j - 1] === "*" ? row[j - 1]! || before : (pattern[j - 1] === "?" || pattern[j - 1] === character) && previous; previous = before; } } return row[pattern.length]!; }
function parseUrl(value: string): RuntimeValue { try { const parsed = new URL(value); return Object.freeze({ host: asciiCase(parsed.hostname, false) }); } catch { return null; } }
function isUrl(value: unknown): value is { readonly host: string } { return typeof value === "object" && value !== null && "host" in value; }
function parseRepository(value: string): RuntimeValue { const match = /^(?:https:\/\/[^/]+\/|git@[^:]+:)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/.exec(value); return match ? Object.freeze({ owner: match[1]!, repository: match[2]! }) : null; }
function isRepository(value: unknown): value is { readonly owner: string; readonly repository: string } { return typeof value === "object" && value !== null && "owner" in value && "repository" in value; }
function normalizeKubernetes(value: string): string { const lower = asciiCase(value, false); return lower.endsWith("ies") ? `${lower.slice(0, -3)}y` : lower.endsWith("s") ? lower.slice(0, -1) : lower; }
function normalizeEndpoint(value: string): string { return `/${value.split("/").filter(Boolean).join("/")}`; }
function requiresKnownOperands(name: string): boolean {
  return !["environmentIsPresent", "environmentIsKnown", "environmentIsUnknown", "missingEnvironmentMayBePresent", "isInPipeline"].includes(name);
}
function matchesLinearRegex(value: string, pattern: string): boolean {
  try { return new RegExp(pattern).test(value); } catch { return false; }
}
function isOptionPredicate(value: CompiledCase["when"]): value is { readonly kind: "option" } { return typeof value === "object" && value !== null && "kind" in value && value.kind === "option"; }
function step(state: string, argvIndex: number, clusterByteIndex: number, source: string, origin: string, action: DslMachineStep["action"], folds: readonly string[], nextState?: string, decision?: PolicyDecision["kind"]): DslMachineStep { return Object.freeze({ state, argvIndex, clusterByteIndex, source, origin, action, folds: Object.freeze([...folds]), ...(nextState === undefined ? {} : { nextState }), ...(decision === undefined ? {} : { decision }) }); }
function frozenEvaluation(decision: PolicyDecision, steps: readonly DslMachineStep[]): DslEvaluation { return Object.freeze({ decision, steps: Object.freeze([...steps]) }); }
