import type { SourceSpan } from "./cst.js";
import type { NormalizedCommand } from "./expand.js";
import { indeterminate, strongestOutcome, type Outcome } from "./outcome.js";
import { policyDeny, safe } from "./outcome.js";
import type { BashDispatchRequest, BashDispatchResult } from "./walker.js";
import { structuralHandlers, unknownStructuralHandler } from "./handlers/registry.js";
import { unknownCommandHandler } from "./handlers/unknown.js";
import { analyzeSecretRedirectInvocation } from "./policies/secrets.js";
import { basename } from "../shell.js";

export interface InvocationCursor {
  readonly invocation: NormalizedCommand;
  readonly index: number;
  readonly options: Readonly<Record<string, unknown>>;
}

/** Context shared by structural traversal and policy observation. */
export interface PolicyDispatchContext {
  /** Effective child environment after command-prefix assignments. */
  readonly environment: BashDispatchRequest["command"]["environment"];
  readonly span: SourceSpan;
  readonly inPipeline: boolean;
  /** Redacted execution-route metadata for policy decisions. */
  readonly provenance: BashDispatchRequest["provenance"];
}

/** Only structural handlers can schedule a statically materialized child script. */
export interface StructuralDispatchContext extends PolicyDispatchContext {
  readonly continueWith: BashDispatchRequest["continueWith"];
}

export interface StructuralHandler {
  readonly name: string;
  handle(cursor: InvocationCursor, context: StructuralDispatchContext): BashDispatchResult;
}

export type PolicyObservation =
  | { readonly kind: "ignore" }
  | { readonly kind: "outcome"; readonly outcome: Outcome };

/** Policy observers cannot recurse or otherwise affect structural traversal. */
export interface PolicyObserver {
  readonly name: string;
  observe(cursor: InvocationCursor, context: PolicyDispatchContext): PolicyObservation;
}

export interface CommandRegistry {
  resolve(executable: string): ResolvedCommand;
}

export interface ResolvedCommand {
  readonly name: string;
  readonly structural: StructuralHandler | null;
  readonly observers: readonly PolicyObserver[];
}

/** Compatibility alias for structural handler implementation modules. */
export type CommandHandler = StructuralHandler;

const IGNORE: PolicyObservation = Object.freeze({ kind: "ignore" });

export function ignorePolicy(): PolicyObservation {
  return IGNORE;
}

export function observePolicy(outcome: Outcome): PolicyObservation {
  return freeze({ kind: "outcome", outcome });
}

/**
 * Builds a name-based registry with exactly one structural continuation owner
 * per executable and any number of independent policy observers.
 */
export function createCommandRegistry(observers: readonly PolicyObserver[] = []): CommandRegistry {
  const structural = new Map<string, StructuralHandler>();
  for (const handler of structuralHandlers) {
    if (structural.has(handler.name)) throw new Error(`duplicate structural Bash handler: ${handler.name}`);
    structural.set(handler.name, handler);
  }
  const registered = new Map<string, PolicyObserver[]>();
  for (const observer of observers) {
    registered.set(observer.name, [...(registered.get(observer.name) ?? []), observer]);
  }
  return Object.freeze({
    resolve(executable: string): ResolvedCommand {
      const owner = structural.get(executable) ?? null;
      const applicable = Object.freeze([...(registered.get(executable) ?? [])]);
      return freeze({
        name: owner?.name ?? applicable[0]?.name ?? unknownStructuralHandler.name,
        structural: owner,
        observers: applicable,
      });
    },
  });
}

const defaultRegistry = createCommandRegistry();

/**
 * Bridges the Task 5 walker callback to one immutable, name-resolved handler.
 * The walker alone executes the returned continuation agenda.
 */
export function dispatchCommand(
  request: BashDispatchRequest,
  registry: CommandRegistry = defaultRegistry,
): BashDispatchResult {
  const redirect = analyzeSecretRedirectInvocation(request.command);
  if (redirect.kind === "deny") return policyDeny(request.span, redirect.evidence);
  const executable = request.command.executable;
  if (!executable) return safe();
  if (executable.kind !== "known") return indeterminate(request.span);

  const cursor: InvocationCursor = freeze({
    invocation: request.command,
    index: 0,
    options: freeze({}),
  });
  const policyContext: PolicyDispatchContext = freeze({
    environment: request.command.environment,
    span: request.span,
    inPipeline: request.inPipeline,
    provenance: request.provenance,
  });
  const context: StructuralDispatchContext = freeze({
    ...policyContext,
    continueWith: request.continueWith,
  });
  const resolved = registry.resolve(handlerName(executable.value));
  const outcomes: Outcome[] = [];
  if (resolved.structural) {
    const structural = resolved.structural.handle(cursor, context);
    if ("kind" in structural) outcomes.push(structural);
    else {
      const outcome = strongestOutcome(observe(resolved.observers, cursor, policyContext, [structural.outcome]));
      if (outcome.kind === "deny") return outcome;
      return freeze({ outcome, continuations: structural.continuations });
    }
  }
  const combined = observe(resolved.observers, cursor, policyContext, outcomes);
  if (outcomes.length === 0) combined.push(unknownStructuralHandler.handle(cursor, context) as Outcome);
  return strongestOutcome(combined);
}

/** Match only an exact final executable component, preserving path-qualified command behavior. */
function handlerName(executable: string): string {
  return executable.includes("/") ? basename(executable) : executable;
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}

function observe(
  observers: readonly PolicyObserver[],
  cursor: InvocationCursor,
  context: PolicyDispatchContext,
  outcomes: Outcome[],
): Outcome[] {
  for (const observer of observers) {
    const observation = observer.observe(cursor, context);
    if (observation.kind === "outcome") outcomes.push(observation.outcome);
  }
  return outcomes;
}
