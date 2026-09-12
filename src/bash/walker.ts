import type { BashCommand, BashFunction, BashProgram, BashStatement, BashWord, SourceSpan } from "./cst.js";
import { parseBashProgram } from "../shell.js";
import { normalizeCommand, type NormalizedCommand } from "./expand.js";
import {
  assignBinding,
  assignLocalBinding,
  endCommandOverlay,
  forkCheckpoint,
  known,
  lookupBinding,
  mergeCheckpoint,
  pushFunctionFrame,
  pushSubshellFrame,
  returnFromFunctionFrame,
  setExported,
  taintFrame,
  unknown,
  type Environment,
  type EnvironmentPatch,
} from "./environment.js";
import { transitionBuiltin } from "./handlers/builtins.js";
import { analysisFailure, indeterminate, policyDeny, safe, strongestOutcome, type Outcome } from "./outcome.js";
import { analyzeSecretRedirectInvocation } from "./policies/secrets.js";
import type { DispatchTarget, Step } from "./runner.js";

export interface BashWalkContext {
  readonly environment: Environment;
  /** Injected by Task 6: the walker has no command-policy registry of its own. */
  readonly dispatchCommand: (request: BashDispatchRequest) => BashDispatchResult;
}

export interface BashDispatchRequest {
  readonly command: NormalizedCommand;
  /** Source provenance for redacted outcome evidence emitted by a command handler. */
  readonly span: SourceSpan;
  readonly environment: Environment;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  /** True when the command receives pipeline input whose contents are not modeled. */
  readonly inPipeline: boolean;
  /** Returns a scheduled nested script without giving dispatch code ambient execution access. */
  readonly continueWith: (
    source: string,
    environment?: Environment,
    options?: BashDispatchContinuationOptions,
  ) => BashDispatchResult;
}

export interface BashDispatchContinuation {
  readonly source: string;
  readonly environment: Environment;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  readonly isolate: boolean;
  /** Explicit caller-state replacement is conservatively unsupported. */
  readonly environmentExplicit: boolean;
  /** Literal code reparsed from a binding must retain redaction provenance. */
  readonly sourceDerivedFromBinding?: boolean;
}

export interface BashDispatchContinuationOptions {
  readonly isolate?: boolean;
  /** The continuation source was materialized from at least one binding. */
  readonly sourceDerivedFromBinding?: boolean;
}

export type BashDispatchResult = Outcome | {
  readonly outcome: Outcome;
  readonly continuations?: readonly BashDispatchContinuation[];
};

interface Path {
  readonly environment: Environment;
  readonly functions: ReadonlyMap<string, readonly BashFunction[]>;
  /** Function names whose call can still resolve to an external command on another path. */
  readonly missingFunctions: ReadonlySet<string>;
  readonly outcomes: readonly Outcome[];
  readonly writes: ReadonlySet<string>;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  readonly returned: boolean;
  readonly sourceDerivedFromBinding: boolean;
}

interface Work {
  readonly statements: readonly BashStatement[];
  readonly index: number;
  readonly path: Path;
  readonly complete: (path: Path) => void;
  readonly skipStatementRedirects?: boolean;
  readonly inPipeline?: boolean;
}

/**
 * Constructs an iterative authorization walk. Command policy is deliberately
 * injected, so this layer only models Bash statement and binding semantics.
 */
export function walkProgram(program: BashProgram, context: BashWalkContext): Step {
  const initial = path(context.environment, new Map(), new Set(), [], new Set(), 0, 0, false, false);
  const target: DispatchTarget = {
    span: programSpan(program),
    functionDepth: 0,
    nestedScriptDepth: 0,
    run: () => evaluateProgram(program, context, initial),
  };
  return freeze({ kind: "continue", state: context.environment, target, span: programSpan(program) });
}

function evaluateProgram(program: BashProgram, context: BashWalkContext, initial: Path): Step {
  const agenda: Work[] = [];
  const completed: Path[] = [];
  let maximumFunctionDepth = 0;
  let maximumNestedScriptDepth = 0;
  let denied: Outcome | undefined;
  let limitFailure: Outcome | undefined;
  let scheduled = 0;
  let steps = 0;

  const schedule = (work: Work): void => {
    if (scheduled >= initial.environment.budgets.workItems) {
      limitFailure ??= analysisFailure("max-work-items", programSpan(program));
      return;
    }
    scheduled++;
    agenda.push(work);
  };
  const finish = (result: Path): void => {
    completed.push(result);
    maximumFunctionDepth = Math.max(maximumFunctionDepth, result.functionDepth);
    maximumNestedScriptDepth = Math.max(maximumNestedScriptDepth, result.nestedScriptDepth);
  };
  schedule({ statements: program.statements, index: 0, path: initial, complete: finish });

  while (agenda.length > 0 && !denied && !limitFailure) {
    const work = agenda.pop()!;
    if (steps >= initial.environment.budgets.steps) {
      limitFailure = analysisFailure("max-steps", statementSpan(work) ?? programSpan(program));
      break;
    }
    steps++;
    if (work.path.returned || work.index >= work.statements.length) {
      work.complete(work.path);
      continue;
    }

    const statement = work.statements[work.index]!;
    const continueWork = (next: Path): void => schedule({
      statements: work.statements,
      index: work.index + 1,
      path: next,
      complete: work.complete,
      inPipeline: work.inPipeline,
    });
    const completeWithDeny = (next: Path): void => {
      const outcome = strongestOutcome(next.outcomes);
      if (outcome.kind === "deny") denied = outcome;
      else continueWork(next);
    };

    if (statement.kind !== "command" && !work.skipStatementRedirects) {
      const retained = retainedRedirectStatements(statement);
      if (retained.length > 0) {
        if (work.path.nestedScriptDepth + 1 > work.path.environment.budgets.nestedScriptDepth) {
          completeWithDeny(addOutcome(work.path, analysisFailure("max-nested-script-depth", statement.span)));
          continue;
        }
        const child = withEnvironment(work.path, pushSubshellFrame(work.path.environment), false, work.path.nestedScriptDepth + 1);
        scheduleNested(retained, child, (finished) => {
          const nested = withEnvironment(
            work.path,
            work.path.environment,
            false,
            work.path.nestedScriptDepth,
            [...work.path.outcomes, ...finished.outcomes.slice(work.path.outcomes.length)],
          );
          if (strongestOutcome(nested.outcomes).kind === "deny") {
            completeWithDeny(nested);
            return;
          }
          schedule({
            statements: work.statements,
            index: work.index,
            path: nested,
            complete: work.complete,
            skipStatementRedirects: true,
          });
        }, schedule);
        continue;
      }
    }

    switch (statement.kind) {
      case "command":
        executeCommand(statement, work.path, context, continueWork, completeWithDeny, schedule, true, work.inPipeline ?? false);
        break;
      case "function":
        continueWork(withFunction(work.path, statement));
        break;
      case "group":
        scheduleNested(statement.statements, work.path, continueWork, schedule);
        break;
      case "subshell": {
        if (work.path.nestedScriptDepth + 1 > work.path.environment.budgets.nestedScriptDepth) {
          completeWithDeny(addOutcome(work.path, analysisFailure("max-nested-script-depth", statement.span)));
          break;
        }
        const child = withEnvironment(work.path, pushSubshellFrame(work.path.environment), false, work.path.nestedScriptDepth + 1);
        scheduleNested(statement.statements, child, (finished) => continueWork(withEnvironment(
          work.path,
          work.path.environment,
          false,
          work.path.nestedScriptDepth,
          [...work.path.outcomes, ...finished.outcomes.slice(work.path.outcomes.length)],
        )), schedule);
        break;
      }
      case "pipeline":
        schedulePipeline(statement.statements, work.path, continueWork, schedule, statement.span);
        break;
      case "if":
        scheduleIf(statement, work.path, continueWork, schedule);
        break;
      case "list":
        scheduleList(statement.statements, statement.operators, work.path, continueWork, schedule);
        break;
      case "unsupported": {
        const builtin = projectedBuiltinCommand(program.source, statement);
        if (builtin) {
          executeCommand(builtin, work.path, context, continueWork, completeWithDeny, schedule, true, work.inPipeline ?? false);
          break;
        }
        if (isLoop(statement)) {
          scheduleUnsupportedLoop(statement, work.path, continueWork, schedule);
          break;
        }
        const tainted = addOutcome(withEnvironment(work.path, taintFrame(work.path.environment, { kind: "unsupported-syntax", span: statement.span })), indeterminate(statement.span));
        scheduleNested(statement.statements, tainted, continueWork, schedule);
        break;
      }
    }
  }

  const terminal = denied ?? limitFailure ?? strongestOutcome(completed.flatMap((result) => result.outcomes));
  const state = completed[0]?.environment ?? initial.environment;
  const finalTarget: DispatchTarget = {
    span: programSpan(program),
    functionDepth: maximumFunctionDepth,
    nestedScriptDepth: maximumNestedScriptDepth,
    run: () => freeze({ kind: "result", state, outcome: terminal, span: programSpan(program) }),
  };
  return freeze({ kind: "continue", state, target: finalTarget, span: programSpan(program) });
}

function executeCommand(
  command: BashCommand,
  input: Path,
  context: BashWalkContext,
  complete: (path: Path) => void,
  completeWithDeny: (path: Path) => void,
  schedule: (work: Work) => void,
  walkRetainedStatements = true,
  inPipeline = false,
): void {
  if (walkRetainedStatements) {
    const retained = retainedStatements(command);
    if (retained.length > 0) {
      if (input.nestedScriptDepth + 1 > input.environment.budgets.nestedScriptDepth) {
        completeWithDeny(addOutcome(input, analysisFailure("max-nested-script-depth", command.span)));
        return;
      }
      const child = withEnvironment(input, pushSubshellFrame(input.environment), false, input.nestedScriptDepth + 1);
      scheduleNested(retained, child, (finished) => {
        const nested = withEnvironment(
          input,
          input.environment,
          false,
          input.nestedScriptDepth,
          [...input.outcomes, ...finished.outcomes.slice(input.outcomes.length)],
        );
        if (strongestOutcome(nested.outcomes).kind === "deny") {
          completeWithDeny(nested);
          return;
        }
        executeCommand(command, nested, context, complete, completeWithDeny, schedule, false, inPipeline);
      }, schedule);
      return;
    }
  }
  const normalized = normalizeCommand(command, input.environment, input.sourceDerivedFromBinding);
  const redirect = analyzeSecretRedirectInvocation(normalized);
  if (redirect.kind === "deny") {
    completeWithDeny(addOutcome(input, policyDeny(command.span, redirect.evidence)));
    return;
  }
  const readonlyAssignment = command.assignments.some((assignment) => lookupBinding(input.environment, assignment.name).readonly);
  if (readonlyAssignment) {
    complete(addOutcome(input, indeterminate(command.span)));
    return;
  }
  if (!normalized.executable) {
    if (normalized.redirects.some((redirect) => redirect.kind === "input")) {
      dispatchNormalized(
        normalized,
        input,
        context,
        completeWithDeny,
        schedule,
        command.span,
        normalized.assignmentPatch.environment,
        inPipeline,
      );
      return;
    }
    complete(withEnvironment(input, normalized.assignmentPatch.environment, false, input.nestedScriptDepth, input.outcomes, appendWrites(input.writes, normalized.assignmentPatch.writes)));
    return;
  }
  if (normalized.executable.kind === "unknown") {
    complete(addOutcome(withEnvironment(input, endCommandOverlay(normalized.environment)), indeterminate(command.span)));
    return;
  }

  const definitions = input.functions.get(normalized.executable.value);
  if (definitions && definitions.length > 0) {
    scheduleFunctionCall(definitions, command, normalized, input, complete, schedule, input.missingFunctions.has(normalized.executable.value));
    return;
  }

  const specialBuiltin = isSpecialBuiltin(normalized.executable.value);
  const builtinEnvironment = specialBuiltin ? persistPrefixAssignments(input.environment, normalized) : input.environment;
  const builtin = transitionBuiltin(normalized, builtinEnvironment, command.span);
  if (builtin.handled) {
    const returnsFromFunction = builtin.returned && input.functionDepth > 0;
    const next = returnsFromFunction
      ? withEnvironment(input, builtin.environment, true, input.nestedScriptDepth, input.outcomes, appendWrites(input.writes, builtin.writes))
      : withEnvironment(input, builtin.environment, false, input.nestedScriptDepth, input.outcomes, appendWrites(input.writes, builtin.writes));
    const transitioned = builtin.outcome ? addOutcome(next, builtin.outcome) : next;
    if (builtin.dispatch) {
      dispatchNormalized(normalized, transitioned, context, completeWithDeny, schedule, command.span, transitioned.environment, inPipeline);
    } else {
      completeWithDeny(transitioned);
    }
    return;
  }

  if (isPossiblyStateMutatingBuiltin(normalized.executable.value)) {
    const tainted = withEnvironment(input, taintFrame(input.environment, { kind: "unmodelled-builtin", span: command.span }));
    dispatchNormalized(normalized, tainted, context, completeWithDeny, schedule, command.span, tainted.environment, inPipeline);
    return;
  }

  if (isBuiltinShellRoute(normalized)) {
    const tainted = addOutcome(
      withEnvironment(input, taintFrame(input.environment, { kind: "builtin-shell-route", span: command.span })),
      indeterminate(command.span),
    );
    dispatchNormalized(normalized, tainted, context, completeWithDeny, schedule, command.span, tainted.environment, inPipeline);
    return;
  }

  dispatchNormalized(normalized, input, context, completeWithDeny, schedule, command.span, undefined, inPipeline);
}

function dispatchNormalized(
  command: NormalizedCommand,
  input: Path,
  context: BashWalkContext,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  span: SourceSpan,
  nextEnvironment = endCommandOverlay(command.environment),
  inPipeline = false,
): void {
  const request: BashDispatchRequest = freeze({
    command,
    span,
    environment: input.environment,
    functionDepth: input.functionDepth,
    nestedScriptDepth: input.nestedScriptDepth,
    inPipeline,
    continueWith: (source, environment, options = {}) => freeze({
      outcome: safe(),
      continuations: Object.freeze([freeze({
        source,
        environment: environment ?? command.environment,
        functionDepth: input.functionDepth,
        nestedScriptDepth: input.nestedScriptDepth + 1,
        isolate: options.isolate ?? true,
        environmentExplicit: environment !== undefined,
        sourceDerivedFromBinding: input.sourceDerivedFromBinding || options.sourceDerivedFromBinding === true,
      })]),
    }),
  });
  const result = normalizeDispatchResult(context.dispatchCommand(request));
  const outcome = hasUnknownOperand(command) ? strongestOutcome([result.outcome, indeterminate(span)]) : result.outcome;
  const next = addOutcome(withEnvironment(input, nextEnvironment), outcome);
  if (!result.continuations || result.continuations.length === 0) {
    complete(next);
    return;
  }

  let remaining = result.continuations.length;
  const completed: Array<{ readonly path: Path; readonly isolate: boolean }> = [];
  const finishContinuations = (): void => {
    const outcomes = completed.flatMap(({ path }) => path.outcomes);
    const nonIsolated = completed.filter((item) => !item.isolate);
    const environment = nonIsolated.length === 0
      ? next.environment
      : mergeCheckpoint(
        forkCheckpoint(next.environment),
        nonIsolated.map(({ path }) => ({ environment: path.environment, writes: path.writes } satisfies EnvironmentPatch)),
      );
    complete(withEnvironment(next, environment, false, next.nestedScriptDepth, outcomes));
  };
  for (let index = result.continuations.length - 1; index >= 0; index--) {
    const continuation = result.continuations[index]!;
    if (!continuation.isolate && continuation.environmentExplicit) {
      completed.push({ path: addOutcome(next, indeterminate(span)), isolate: false });
      remaining--;
      continue;
    }
    if (continuation.nestedScriptDepth > continuation.environment.budgets.nestedScriptDepth) {
      completed.push({ path: addOutcome(next, analysisFailure("max-nested-script-depth", span)), isolate: continuation.isolate });
      remaining--;
      continue;
    }
    const parsed = parseBashProgram(continuation.source);
    if (parsed.kind === "parse-failure") {
      completed.push({ path: addOutcome(next, indeterminate(parsed.span)), isolate: continuation.isolate });
      remaining--;
      continue;
    }
    const childEnvironment = continuation.isolate ? pushSubshellFrame(continuation.environment) : continuation.environment;
    const child = withSourceBindingProvenance(
      resetWrites(withEnvironment(next, childEnvironment, false, continuation.nestedScriptDepth)),
      continuation.sourceDerivedFromBinding === true,
    );
    scheduleNested(parsed.statements, child, (finished) => {
      completed.push({ path: finished, isolate: continuation.isolate });
      remaining--;
      if (remaining !== 0) return;
      finishContinuations();
    }, schedule);
  }
  if (remaining === 0) finishContinuations();
}

function isPossiblyStateMutatingBuiltin(executable: string): boolean {
  return [
    "alias", "cd", "compgen", "complete", "declare", "dirs", "disown", "enable", "fc", "getopts", "history", "jobs",
    "let", "mapfile", "popd", "printf", "pushd", "readarray", "set", "shift", "trap", "typeset", "ulimit", "umask", "unalias", "wait",
  ].includes(executable);
}

function isBuiltinShellRoute(command: NormalizedCommand): boolean {
  if (command.executable?.kind !== "known" || command.executable.value !== "builtin") return false;
  const target = command.argv[0];
  return target?.kind === "known" && ["eval", "source", "."].includes(target.value);
}

function normalizeDispatchResult(result: BashDispatchResult): { readonly outcome: Outcome; readonly continuations?: readonly BashDispatchContinuation[] } {
  return "kind" in result ? { outcome: result } : result;
}

function hasUnknownOperand(command: NormalizedCommand): boolean {
  return command.argv.some((argument) => argument.kind === "unknown")
    || command.redirects.some((redirect) => redirect.target?.kind === "unknown");
}

function isSpecialBuiltin(executable: string): boolean {
  return [".", "eval", "export", "readonly", "return", "source", "unset"].includes(executable);
}

function persistPrefixAssignments(environment: Environment, normalized: NormalizedCommand): Environment {
  let persistent = environment;
  for (const name of normalized.assignmentPatch.writes) {
    persistent = assignBinding(persistent, name, lookupBinding(normalized.environment, name).value);
  }
  return persistent;
}

function scheduleFunctionCall(
  definitions: readonly BashFunction[],
  command: BashCommand,
  normalized: NormalizedCommand,
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  mayResolveExternally: boolean,
): void {
  if (mayResolveExternally) {
    complete(addOutcome(
      withEnvironment(input, taintFrame(input.environment, { kind: "branch-function-absence", span: command.span })),
      indeterminate(command.span),
    ));
  }
  for (let index = definitions.length - 1; index >= 0; index--) {
    const definition = definitions[index]!;
    let frame = pushFunctionFrame(input.environment);
    for (const name of normalized.assignmentPatch.writes) {
      frame = assignLocalBinding(frame, name, lookupBinding(normalized.environment, name).value);
      frame = setExported(frame, name, lookupBinding(normalized.environment, name).exported);
    }
    normalized.argv.forEach((argument, argumentIndex) => {
      frame = assignLocalBinding(frame, String(argumentIndex + 1), argument.kind === "known"
        ? known(argument.value)
        : unknown({ kind: argument.reason.kind, span: argument.reason.span }));
    });
    const called = withEnvironment(input, frame, false, input.nestedScriptDepth, input.outcomes, input.writes, input.functionDepth + 1);
    if (called.functionDepth > called.environment.budgets.functionDepth) {
      complete(addOutcome(called, analysisFailure("max-function-depth", command.span)));
      continue;
    }
    scheduleNested([definition.body], called, (finished) => complete(withEnvironment(
      finished,
      returnFromFunctionFrame(finished.environment),
      false,
      input.nestedScriptDepth,
    )), schedule);
  }
}

function scheduleNested(
  statements: readonly BashStatement[],
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  inPipeline = false,
): void {
  schedule({ statements, index: 0, path: input, complete, inPipeline });
}

function schedulePipeline(
  statements: readonly BashStatement[],
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  span: SourceSpan,
): void {
  if (statements.length === 0) {
    complete(input);
    return;
  }
  if (input.nestedScriptDepth + 1 > input.environment.budgets.nestedScriptDepth) {
    complete(addOutcome(input, analysisFailure("max-nested-script-depth", span)));
    return;
  }
  let remaining = statements.length;
  const outcomes: Outcome[] = [];
  for (let index = statements.length - 1; index >= 0; index--) {
    const child = withEnvironment(input, pushSubshellFrame(input.environment), false, input.nestedScriptDepth + 1);
    scheduleNested([statements[index]!], child, (finished) => {
      outcomes.push(...finished.outcomes.slice(input.outcomes.length));
      remaining--;
      if (remaining === 0) complete(withEnvironment(input, input.environment, false, input.nestedScriptDepth, [...input.outcomes, ...outcomes]));
    }, schedule, true);
  }
}

/** Unsupported loops may run zero, once, or repeatedly; never collapse them to one write path. */
function scheduleUnsupportedLoop(
  statement: Extract<BashStatement, { kind: "unsupported" }>,
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
): void {
  const checkpoint = forkCheckpoint(input.environment);
  const zero = resetWrites(addOutcome(input, indeterminate(statement.span)));
  const branches: Path[] = [zero];
  const finish = (branch: Path): void => {
    branches.push(branch);
    if (branches.length !== 3) return;
    const merged = mergeCheckpoint(checkpoint, branches.map((item) => ({ environment: item.environment, writes: item.writes } satisfies EnvironmentPatch)));
    complete(withEnvironment(input, merged, false, input.nestedScriptDepth, branches.flatMap((item) => item.outcomes)));
  };
  const body = resetWrites(addOutcome(withEnvironment(input, taintFrame(input.environment, { kind: "unsupported-loop", span: statement.span })), indeterminate(statement.span)));
  scheduleNested(statement.statements, body, finish, schedule);
  scheduleNested([...statement.statements, ...statement.statements], body, finish, schedule);
}

function isLoop(statement: Extract<BashStatement, { kind: "unsupported" }>): boolean {
  return /(?:for|while|until).*statement/.test(statement.reason);
}

function scheduleIf(
  statement: Extract<BashStatement, { kind: "if" }>,
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
): void {
  scheduleNested(statement.condition, input, (condition) => {
    if (condition.returned) {
      complete(condition);
      return;
    }
    const checkpoint = forkCheckpoint(condition.environment);
    const branches = [statement.consequent, statement.alternate];
    const finished: Path[] = [];
    for (let index = branches.length - 1; index >= 0; index--) {
      scheduleNested(branches[index]!, resetWrites(condition), (branch) => {
        finished.push(branch);
        if (finished.length !== branches.length) return;
        const merged = mergeCheckpoint(checkpoint, finished.map((item) => ({ environment: item.environment, writes: item.writes } satisfies EnvironmentPatch)));
        const joined = withEnvironment(condition, merged, finished.every((item) => item.returned), condition.nestedScriptDepth, finished.flatMap((item) => item.outcomes));
        const functions = mergeFunctions(finished);
        complete(withFunctions(joined, functions.functions, functions.missing));
      }, schedule);
    }
  }, schedule);
}

function scheduleList(
  statements: readonly BashStatement[],
  operators: readonly ("&&" | "||")[],
  input: Path,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
): void {
  const advance = (index: number, current: Path): void => {
    if (current.returned || index >= statements.length) {
      complete(current);
      return;
    }
    scheduleNested([statements[index]!], current, (finished) => {
      const operator = operators[index];
      if (!operator || finished.returned) {
        advance(index + 1, finished);
        return;
      }
      // A command's status is not statically known, so both the short-circuit
      // and continuing paths remain reachable for authorization analysis.
      advance(index + 1, finished);
      complete(finished);
    }, schedule);
  };
  advance(0, input);
}

function path(
  environment: Environment,
  functions: ReadonlyMap<string, readonly BashFunction[]>,
  missingFunctions: ReadonlySet<string>,
  outcomes: readonly Outcome[],
  writes: ReadonlySet<string>,
  functionDepth: number,
  nestedScriptDepth: number,
  returned: boolean,
  sourceDerivedFromBinding: boolean,
): Path {
  return freeze({
    environment,
    functions: new Map(functions),
    missingFunctions: new Set(missingFunctions),
    outcomes: Object.freeze([...outcomes]),
    writes: new Set(writes),
    functionDepth,
    nestedScriptDepth,
    returned,
    sourceDerivedFromBinding,
  });
}

function withEnvironment(
  input: Path,
  environment: Environment,
  returned = input.returned,
  nestedScriptDepth = input.nestedScriptDepth,
  outcomes = input.outcomes,
  writes: ReadonlySet<string> = input.writes,
  functionDepth = input.functionDepth,
): Path {
  return path(
    environment,
    input.functions,
    input.missingFunctions,
    outcomes,
    writes,
    functionDepth,
    nestedScriptDepth,
    returned,
    input.sourceDerivedFromBinding,
  );
}

function withFunction(input: Path, definition: BashFunction): Path {
  const functions = new Map(input.functions);
  const missingFunctions = new Set(input.missingFunctions);
  functions.set(definition.name, Object.freeze([definition]));
  missingFunctions.delete(definition.name);
  return path(input.environment, functions, missingFunctions, input.outcomes, input.writes, input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding);
}

function withFunctions(input: Path, functions: ReadonlyMap<string, readonly BashFunction[]>, missingFunctions: ReadonlySet<string>): Path {
  return path(input.environment, functions, missingFunctions, input.outcomes, input.writes, input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding);
}

/** Preserves every branch-reachable definition so a later call walks them all. */
function mergeFunctions(branches: readonly Path[]): { readonly functions: ReadonlyMap<string, readonly BashFunction[]>; readonly missing: ReadonlySet<string> } {
  const merged = new Map<string, BashFunction[]>();
  const missing = new Set<string>();
  const names = new Set<string>();
  for (const branch of branches) for (const name of branch.functions.keys()) names.add(name);
  for (const branch of branches) {
    for (const [name, definitions] of branch.functions) {
      const candidates = merged.get(name) ?? [];
      for (const definition of definitions) if (!candidates.includes(definition)) candidates.push(definition);
      merged.set(name, candidates);
    }
  }
  for (const name of names) {
    if (branches.some((branch) => !branch.functions.has(name) || branch.missingFunctions.has(name))) missing.add(name);
  }
  return freeze({ functions: merged, missing });
}

function resetWrites(input: Path): Path {
  return path(input.environment, input.functions, input.missingFunctions, input.outcomes, new Set(), input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding);
}

function appendWrites(existing: ReadonlySet<string>, next: ReadonlySet<string> | readonly string[]): ReadonlySet<string> {
  return new Set([...existing, ...next]);
}

function addOutcome(input: Path, outcome: Outcome): Path {
  return path(input.environment, input.functions, input.missingFunctions, [...input.outcomes, outcome], input.writes, input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding);
}

function withSourceBindingProvenance(input: Path, sourceDerivedFromBinding: boolean): Path {
  return path(
    input.environment,
    input.functions,
    input.missingFunctions,
    input.outcomes,
    input.writes,
    input.functionDepth,
    input.nestedScriptDepth,
    input.returned,
    sourceDerivedFromBinding,
  );
}

function programSpan(program: BashProgram): SourceSpan {
  return Object.freeze({ start: 0, end: program.source.length });
}

function statementSpan(work: Work): SourceSpan | undefined {
  return work.statements[work.index]?.span;
}

/** Finds command substitutions and retained unsupported syntax in source order. */
function retainedStatements(command: BashCommand): readonly BashStatement[] {
  const ordered: Array<{ readonly statement: BashStatement; readonly index: number }> = [];
  let index = 0;
  const collect = (word: BashWord): void => {
    switch (word.kind) {
      case "command-substitution":
      case "expansion":
      case "unsupported-word":
        for (const statement of word.statements) ordered.push({ statement, index: index++ });
        break;
      case "concatenation":
        for (const part of word.parts) collect(part);
        break;
      case "word":
        break;
    }
  };
  for (const assignment of command.assignments) if (assignment.value) collect(assignment.value);
  for (const word of command.words) collect(word);
  for (const redirect of command.redirects) for (const word of redirect.words) collect(word);
  return ordered
    .sort((left, right) => left.statement.span.start - right.statement.span.start || left.index - right.index)
    .map(({ statement }) => statement);
}

function retainedRedirectStatements(statement: Exclude<BashStatement, BashCommand>): readonly BashStatement[] {
  const redirects = "redirects" in statement ? statement.redirects : undefined;
  if (!redirects) return Object.freeze([]);
  const ordered: Array<{ readonly statement: BashStatement; readonly index: number }> = [];
  let index = 0;
  const collect = (word: BashWord): void => {
    switch (word.kind) {
      case "command-substitution":
      case "expansion":
      case "unsupported-word":
        for (const nested of word.statements) ordered.push({ statement: nested, index: index++ });
        break;
      case "concatenation":
        for (const part of word.parts) collect(part);
        break;
      case "word":
        break;
    }
  };
  for (const redirect of redirects) for (const word of redirect.words) collect(word);
  return ordered
    .sort((left, right) => left.statement.span.start - right.statement.span.start || left.index - right.index)
    .map(({ statement: nested }) => nested);
}

/**
 * tree-sitter-bash currently projects declaration and unset commands as
 * unsupported nodes. Their bounded, stateful forms are still recognizable from
 * the immutable source span, so Task 5 reconstitutes only those commands for
 * the dedicated builtin transition layer.
 */
function projectedBuiltinCommand(source: string, statement: Extract<BashStatement, { kind: "unsupported" }>): BashCommand | undefined {
  if (!statement.reason.includes("declaration_command") && !statement.reason.includes("unset_command")) return undefined;
  const text = source.slice(statement.span.start, statement.span.end);
  const words = splitWords(text, statement.span.start);
  const executable = words[0];
  if (!executable || executable.kind !== "word" || !["local", "export", "readonly", "unset"].includes(executable.text)) return undefined;
  return freeze({
    kind: "command",
    assignments: Object.freeze([]),
    words: Object.freeze(words),
    redirects: Object.freeze([...(statement.redirects ?? [])]),
    span: statement.span,
  });
}

function splitWords(text: string, offset: number): BashWord[] {
  const words: BashWord[] = [];
  let start = -1;
  let quote: "single" | "double" | undefined;
  let escaped = false;
  const finish = (end: number): void => {
    if (start < 0) return;
    words.push(freeze({ kind: "word", text: text.slice(start, end), span: { start: offset + start, end: offset + end } }));
    start = -1;
  };
  for (let index = 0; index < text.length; index++) {
    const character = text[index]!;
    if (start < 0 && /\s/.test(character)) continue;
    if (start < 0) start = index;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "single") {
      escaped = true;
      continue;
    }
    if (character === "'" && quote !== "double") quote = quote === "single" ? undefined : "single";
    else if (character === '"' && quote !== "single") quote = quote === "double" ? undefined : "double";
    else if (!quote && /\s/.test(character)) finish(index);
  }
  finish(text.length);
  return words;
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
