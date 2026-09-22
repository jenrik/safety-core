import type { SourceSpan } from "./cst.js";
import type { NormalizedCommand } from "./expand.js";
import { indeterminate, strongestOutcome, withPolicySpan, type Outcome } from "./outcome.js";
import { policyDeny, safe } from "./outcome.js";
import type { BashDispatchRequest, BashDispatchResult, BashPreflightRequest, BashPreflightResult } from "./walker.js";
import { structuralHandlers, unknownStructuralHandler } from "./handlers/registry.js";
import { unknownCommandHandler } from "./handlers/unknown.js";
import { analyzeSecretRedirectInvocation } from "./policies/secrets.js";
import { basename } from "../shell.js";
import { projectExecutionGapEvent, projectInvocationEvent } from "../policy/events.js";

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
  /** Emit a generic execution gap before a structural preflight stops traversal. */
  readonly recordExecutionGap?: (reason: import("./walker.js").ExecutionUnknownReason, processEffect: import("./walker.js").ProcessEffect) => void;
}

/** Only structural handlers can schedule a statically materialized child script. */
export interface StructuralDispatchContext extends PolicyDispatchContext {
  readonly continueWithSource: BashDispatchRequest["continueWithSource"];
  readonly continueWithInvocation: BashDispatchRequest["continueWithInvocation"];
  readonly continueWithOpaque: BashDispatchRequest["continueWithOpaque"];
}

export interface StructuralHandler {
  readonly name: string;
  preflight?(cursor: InvocationCursor, context: PolicyDispatchContext): BashPreflightResult;
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
const CONTINUE_PREFLIGHT: BashPreflightResult = Object.freeze({ kind: "continue" });

export function ignorePolicy(): PolicyObservation {
  return IGNORE;
}

export function observePolicy(outcome: Outcome): PolicyObservation {
  return freeze({ kind: "outcome", outcome });
}

export function continuePreflight(): BashPreflightResult {
  return CONTINUE_PREFLIGHT;
}

/**
 * Builds a name-based registry with exactly one structural child owner
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

/** Structural deny-only pass over normalized words before substitution work is admitted. */
export function preflightCommand(
  request: BashPreflightRequest,
  registry: CommandRegistry = defaultRegistry,
): BashPreflightResult {
  const executable = request.command.executable;
  if (!executable || executable.kind !== "known") return CONTINUE_PREFLIGHT;
  const structural = registry.resolve(handlerName(executable.value)).structural;
  if (!structural?.preflight) return CONTINUE_PREFLIGHT;
  const cursor: InvocationCursor = freeze({ invocation: request.command, index: 0, options: freeze({}) });
  const result = structural.preflight(cursor, freeze({
    environment: request.command.environment,
    span: request.span,
    inPipeline: request.inPipeline,
    provenance: request.provenance,
    recordExecutionGap: (reason, processEffect) => request.recordPolicyEvent?.(projectExecutionGapEvent(reason, {
      environment: request.command.environment,
      span: request.span,
      provenance: request.provenance,
      inPipeline: request.inPipeline,
      processEffect,
    })),
  }));
  return result.kind === "deny" ? result : CONTINUE_PREFLIGHT;
}

/**
 * Bridges the Task 5 walker callback to one immutable, name-resolved handler.
 * The walker alone executes the returned child agenda.
 */
export function dispatchCommand(
  request: BashDispatchRequest,
  registry: CommandRegistry = defaultRegistry,
): BashDispatchResult {
  const event = projectInvocationEvent(request.command, {
    environment: request.command.environment,
    span: request.span,
    provenance: request.provenance,
    inPipeline: request.inPipeline,
    processEffect: request.processEffect,
    cwd: request.cwd,
    executableFilesystem: request.executableFilesystem,
  });
  request.recordPolicyEvent?.(event);
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
    continueWithSource: request.continueWithSource,
    continueWithInvocation: request.continueWithInvocation,
    continueWithOpaque: request.continueWithOpaque,
  });
  const resolved = registry.resolve(handlerName(executable.value));
  const outcomes: Outcome[] = [];
  if (resolved.structural) {
    const structural = resolved.structural.handle(cursor, context);
    if ("kind" in structural) {
      outcomes.push(structural);
      if (structural.kind === "indeterminate" || structural.kind === "failure") {
        const opaque = request.continueWithOpaque("structural-parse-failure");
        if ("kind" in opaque) outcomes.push(opaque);
        else {
          recordExecutionGaps(request, opaque.children ?? []);
          const outcome = strongestOutcome(observe(resolved.observers, cursor, policyContext, [structural, opaque.outcome]));
          if (outcome.kind === "deny") return outcome;
          return freeze({ outcome, children: opaque.children });
        }
      }
    }
    else {
      recordExecutionGaps(request, structural.children ?? []);
      const outcome = strongestOutcome(observe(resolved.observers, cursor, policyContext, [structural.outcome]));
      if (outcome.kind === "deny") return outcome;
      return freeze({ outcome, children: structural.children });
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

function recordExecutionGaps(
  request: BashDispatchRequest,
  children: readonly { readonly target: { readonly kind: string; readonly reason?: string }; readonly environment: BashDispatchRequest["command"]["environment"]; readonly provenance: BashDispatchRequest["provenance"]; readonly inPipeline: boolean; readonly processEffect: BashDispatchRequest["processEffect"] }[],
): void {
  for (const child of children) {
    if (child.target.kind !== "opaque" || !child.target.reason) continue;
    request.recordPolicyEvent?.(projectExecutionGapEvent(child.target.reason, {
      environment: child.environment,
      span: request.span,
      provenance: child.provenance,
      inPipeline: child.inPipeline,
      processEffect: child.processEffect,
    }));
  }
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
    if (observation.kind === "outcome") outcomes.push(withPolicySpan(observation.outcome, context.span));
  }
  return outcomes;
}
