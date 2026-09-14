import type { SourceSpan } from "./cst.js";
import type { NormalizedCommand } from "./expand.js";
import { indeterminate, strongestOutcome, type Outcome } from "./outcome.js";
import { policyDeny, safe } from "./outcome.js";
import type { BashDispatchContinuation, BashDispatchRequest, BashDispatchResult } from "./walker.js";
import { structuralHandlers } from "./handlers/registry.js";
import { unknownCommandHandler } from "./handlers/unknown.js";
import { analyzeSecretRedirectInvocation } from "./policies/secrets.js";
import { basename } from "../shell.js";

export interface InvocationCursor {
  readonly invocation: NormalizedCommand;
  readonly index: number;
  readonly options: Readonly<Record<string, unknown>>;
}

/** The handler boundary exposes only static continuation scheduling, never process execution. */
export interface DispatchContext {
  readonly continueWith: BashDispatchRequest["continueWith"];
  /** Effective child environment after command-prefix assignments. */
  readonly environment: BashDispatchRequest["command"]["environment"];
  readonly span: SourceSpan;
  readonly inPipeline: boolean;
}

/** A handler emits only redacted analysis evidence and/or walker continuations. */
export interface CommandHandler {
  readonly name: string;
  handle(cursor: InvocationCursor, context: DispatchContext): BashDispatchResult;
}

export interface CommandRegistry {
  resolve(executable: string): CommandHandler;
}

/**
 * Builds a name-based registry. Caller policy handlers compose with built-in
 * structural handlers, so policy evidence cannot suppress nested recursion.
 * TODO: Separate structural recursion from policy observation so only one
 * handler can schedule each nested script and no handler reparses its child.
 */
export function createCommandRegistry(handlers: readonly CommandHandler[] = []): CommandRegistry {
  const registered = new Map<string, CommandHandler[]>();
  for (const handler of [...handlers, ...structuralHandlers]) {
    registered.set(handler.name, [...(registered.get(handler.name) ?? []), handler]);
  }
  return Object.freeze({
    resolve(executable: string): CommandHandler {
      const handlersForName = registered.get(executable);
      return handlersForName ? compose(executable, handlersForName) : unknownCommandHandler;
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
  const context: DispatchContext = freeze({
    continueWith: request.continueWith,
    environment: request.command.environment,
    span: request.span,
    inPipeline: request.inPipeline,
  });
  return registry.resolve(handlerName(executable.value)).handle(cursor, context);
}

/** Match only an exact final executable component, preserving path-qualified command behavior. */
function handlerName(executable: string): string {
  return executable.includes("/") ? basename(executable) : executable;
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}

function compose(name: string, handlers: readonly CommandHandler[]): CommandHandler {
  return freeze({
    name,
    handle(cursor: InvocationCursor, context: DispatchContext): BashDispatchResult {
      const outcomes: Outcome[] = [];
      const continuations: BashDispatchContinuation[] = [];
      for (const handler of handlers) {
        const result = handler.handle(cursor, context);
        if ("kind" in result) {
          outcomes.push(result);
          continue;
        }
        outcomes.push(result.outcome);
        if (result.continuations) continuations.push(...result.continuations);
      }
      const outcome = strongestOutcome(outcomes);
      return continuations.length === 0
        ? outcome
        : freeze({ outcome, continuations: Object.freeze(continuations) });
    },
  });
}
