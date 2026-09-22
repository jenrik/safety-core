import type { BashCommand, BashFunction, BashProgram, BashStatement, BashWord, SourceSpan } from "./cst.js";
import { parseBashProgram } from "../shell.js";
import { expandWord, normalizeCommand, normalizedInvocation, type NormalizedCommand, type ResolvedWord } from "./expand.js";
import {
  assignBinding,
  assignLocalBinding,
  endCommandOverlay,
  known,
  lookupBinding,
  pushFunctionFrame,
  pushSubshellFrame,
  returnFromFunctionFrame,
  setExported,
  taintFrame,
  unknown,
  type Environment,
} from "./environment.js";
import {
  completeShellState,
  defineShellFunction,
  forkShellState,
  initialShellState,
  joinShellStates,
  taintShellState,
  withShellEnvironment,
  type BashShellState,
} from "./state.js";
import { transitionBuiltin } from "./handlers/builtins.js";
import {
  analysisFailure,
  appendOutcomeSummary,
  emptyOutcomeSummary,
  indeterminate,
  materializeOutcomeSummary,
  mergeOutcomeSummaries,
  outcomeSummaryIsDeny,
  dynamicExecutableIndeterminate,
  failure,
  policyDeny,
  policyIndeterminate,
  safe,
  strongestOutcome,
  type AnalysisBudget,
  type Outcome,
  type OutcomeSummary,
} from "./outcome.js";
import { analyzeSecretRedirectInvocation } from "./policies/secrets.js";
import type { DispatchTarget, Step } from "./runner.js";
import { projectExecutionGapEvent, projectInvocationEvent } from "../policy/events.js";
import type { BashPolicyEvent } from "../policy/types.js";

export interface BashWalkContext {
  readonly environment: Environment;
  /** Injected by Task 6: the walker has no command-policy registry of its own. */
  readonly dispatchCommand: (request: BashDispatchRequest) => BashDispatchResult;
  /** Deny-only structural check that runs before retained substitutions. */
  readonly preflightCommand: (request: BashPreflightRequest) => BashPreflightResult;
  /** Shadow-only generic policy trace sink; it cannot alter traversal. */
  readonly recordPolicyEvent?: (event: BashPolicyEvent) => void;
}

/** Metadata-only execution route; never contains source, arguments, or values. */
export type BashExecutionRoute =
  | "direct"
  | "transparent-wrapper"
  | "eval"
  | "source"
  | "shell-startup"
  | "shell-command"
  | "binding-derived-script";

export interface BashExecutionProvenance {
  readonly route: readonly BashExecutionRoute[];
}

const DIRECT_PROVENANCE: BashExecutionProvenance = Object.freeze({ route: Object.freeze(["direct"]) });

export interface BashDispatchRequest {
  readonly command: NormalizedCommand;
  /** Source provenance for redacted outcome evidence emitted by a command handler. */
  readonly span: SourceSpan;
  readonly environment: Environment;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  /** True when the command receives pipeline input whose contents are not modeled. */
  readonly inPipeline: boolean;
  readonly provenance: BashExecutionProvenance;
  readonly processEffect: ProcessEffect;
  /** Optional immutable event sink used by generic shadow policy evaluation. */
  readonly recordPolicyEvent?: (event: BashPolicyEvent) => void;
  /** Returns a scheduled nested script without giving dispatch code ambient execution access. */
  readonly continueWithSource: (
    source: string,
    environment?: Environment,
    options?: BashChildExecutionOptions,
  ) => BashDispatchResult;
  /** Schedules an argv child directly, without interpreting its words as Bash source. */
  readonly continueWithInvocation: (
    words: readonly ResolvedWord[],
    environment?: Environment,
    options?: BashChildExecutionOptions,
  ) => BashDispatchResult;
  /** Records an execution route whose child representation is unsupported. */
  readonly continueWithOpaque: (
    reason: ExecutionUnknownReason,
    environment?: Environment,
    options?: BashChildExecutionOptions,
  ) => BashDispatchResult;
}

export type BashPreflightRequest = Pick<
  BashDispatchRequest,
  "command" | "span" | "environment" | "inPipeline" | "provenance"
>;

export type BashPreflightResult =
  | { readonly kind: "continue" }
  | Extract<Outcome, { readonly kind: "deny" }>;

/** Redacted classifications only; never include source, argv, paths, or values. */
export type ExecutionUnknownReason =
  | "structural-parse-failure"
  | "source-parse-failure"
  | "source-file-execution"
  | "shell-startup-execution"
  | "unsupported-execution";

export type ProcessEffect =
  | "none"
  | "exec-replace"
  | "spawn-and-wait"
  | "spawn-async"
  | "spawn-repeated"
  | "unknown";

export type BashExecutionTarget =
  | {
    readonly kind: "invocation";
    readonly command: NormalizedCommand;
  }
  | {
    readonly kind: "statements";
    readonly statements: readonly BashStatement[];
  }
  | {
    readonly kind: "source";
    readonly source: string;
    readonly dialect: "bash";
    readonly sourceDerivedFromBinding: boolean;
  }
  | {
    readonly kind: "opaque";
    readonly reason: ExecutionUnknownReason;
  };

export interface BashChildExecution {
  readonly target: BashExecutionTarget;
  readonly processEffect: ProcessEffect;
  readonly environment: Environment;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  /** Pipeline stdin remains unknown through transparent wrapper children. */
  readonly inPipeline: boolean;
  readonly isolate: boolean;
  /** Explicit caller-state replacement is conservatively unsupported. */
  readonly environmentExplicit: boolean;
  readonly provenance: BashExecutionProvenance;
}

export interface BashChildExecutionOptions {
  readonly isolate?: boolean;
  readonly route?: Exclude<BashExecutionRoute, "direct" | "binding-derived-script">;
  /** The source target was materialized from at least one binding. */
  readonly sourceDerivedFromBinding?: boolean;
  readonly processEffect?: ProcessEffect;
}

export type BashDispatchResult = Outcome | {
  readonly outcome: Outcome;
  readonly children?: readonly BashChildExecution[];
};

interface Path {
  readonly state: BashShellState;
  readonly outcome: OutcomeSummary;
  readonly writes: ReadonlySet<string>;
  readonly functionDepth: number;
  readonly nestedScriptDepth: number;
  readonly returned: boolean;
  readonly sourceDerivedFromBinding: boolean;
  readonly provenance: BashExecutionProvenance;
  readonly processEffect: ProcessEffect;
}

interface StatementWork {
  readonly kind: "statements";
  readonly statements: readonly BashStatement[];
  readonly index: number;
  readonly path: Path;
  readonly complete: (path: Path) => void;
  readonly skipStatementRedirects?: boolean;
  readonly inPipeline?: boolean;
}

interface InvocationWork {
  readonly kind: "invocation";
  readonly command: NormalizedCommand;
  readonly path: Path;
  readonly complete: (path: Path) => void;
  readonly span: SourceSpan;
  readonly inPipeline: boolean;
}

type Work = StatementWork | InvocationWork;

/**
 * Constructs an iterative authorization walk. Command policy is deliberately
 * injected, so this layer only models Bash statement and binding semantics.
 */
export function walkProgram(program: BashProgram, context: BashWalkContext, trailingOutcome?: Outcome): Step {
  const initial = path(initialShellState(context.environment), emptyOutcomeSummary(), new Set(), 0, 0, false, false, DIRECT_PROVENANCE, "none");
  const target: DispatchTarget = {
    span: programSpan(program),
    functionDepth: 0,
    nestedScriptDepth: 0,
    run: () => evaluateProgram(program, context, initial, trailingOutcome),
    reportExecutionGap: (reason, environment, span) => context.recordPolicyEvent?.(projectExecutionGapEvent(reason, {
      environment,
      span,
      provenance: DIRECT_PROVENANCE,
      inPipeline: false,
      processEffect: "none",
    })),
  };
  return freeze({ kind: "continue", state: context.environment, target, span: programSpan(program) });
}

function evaluateProgram(program: BashProgram, context: BashWalkContext, initial: Path, trailingOutcome?: Outcome): Step {
  const agenda: Work[] = [];
  const completed: Path[] = [];
  let denied: Outcome | undefined;
  let limitFailure: Outcome | undefined;
  let scheduled = 0;
  let steps = 0;

  const schedule = (work: Work): void => {
    if (scheduled >= initial.state.environment.budgets.workItems) {
      limitFailure ??= analysisFailure("max-work-items", programSpan(program));
      recordWorkGap(context, work, "max-work-items", programSpan(program));
      return;
    }
    scheduled++;
    agenda.push(work);
  };
  const finish = (result: Path): void => {
    completed.push(result);
  };
  schedule({
    kind: "statements",
    statements: program.statements,
    index: 0,
    path: initial,
    complete: (completedPath) => finish(trailingOutcome ? addOutcome(completedPath, trailingOutcome) : completedPath),
  });

  // maxWorkItems limits admission. Once exhausted, already-admitted work still
  // drains so a concrete denial cannot be hidden by a later admission failure.
  while (agenda.length > 0 && !denied) {
    const work = agenda.pop()!;
    if (steps >= initial.state.environment.budgets.steps) {
      limitFailure ??= analysisFailure("max-steps", statementSpan(work) ?? programSpan(program));
      recordWorkGap(context, work, "max-steps", statementSpan(work) ?? programSpan(program));
      for (const pending of agenda) recordWorkGap(context, pending, "max-steps", statementSpan(pending) ?? programSpan(program));
      break;
    }
    steps++;
    if (work.kind === "invocation") {
      executeNormalizedInvocation(
        work.command,
        work.path,
        context,
        work.complete,
        schedule,
        work.span,
        work.inPipeline,
      );
      continue;
    }
    if (work.path.returned || work.index >= work.statements.length) {
      work.complete(work.path);
      continue;
    }

    const statement = work.statements[work.index]!;
    const continueWork = (next: Path): void => schedule({
      kind: "statements",
      statements: work.statements,
      index: work.index + 1,
      path: next,
      complete: work.complete,
      inPipeline: work.inPipeline,
    });
    const completeWithDeny = (next: Path): void => {
      if (outcomeSummaryIsDeny(next.outcome)) denied = materializeOutcomeSummary(next.outcome);
      else continueWork(next);
    };

    if (statement.kind !== "command" && !work.skipStatementRedirects) {
      const retained = retainedRedirectStatements(statement);
      const hasRedirect = "redirects" in statement && (statement.redirects?.length ?? 0) > 0;
      const secretRedirect = analyzeStatementSecretRedirects(statement, work.path.state.environment);
      if (secretRedirect?.kind === "deny") {
        completeWithDeny(addOutcome(work.path, policyDeny(statement.span, secretRedirect.evidence)));
        continue;
      }
      if (retained.length > 0) {
        if (work.path.nestedScriptDepth + 1 > work.path.state.environment.budgets.nestedScriptDepth) {
          recordPathGap(context, work.path, "max-nested-script-depth", statement.span, work.inPipeline ?? false);
          completeWithDeny(addOutcome(work.path, analysisFailure("max-nested-script-depth", statement.span)));
          continue;
        }
        const child = hasRedirect
          ? addOutcome(
            withEnvironment(work.path, pushSubshellFrame(work.path.state.environment), false, work.path.nestedScriptDepth + 1),
            indeterminate(statement.span),
          )
          : withEnvironment(work.path, pushSubshellFrame(work.path.state.environment), false, work.path.nestedScriptDepth + 1);
        scheduleNested(retained, child, (finished) => {
          const nested = withEnvironment(
            work.path,
            work.path.state.environment,
            false,
            work.path.nestedScriptDepth,
            finished.outcome,
          );
          if (outcomeSummaryIsDeny(nested.outcome)) {
            completeWithDeny(nested);
            return;
          }
          schedule({
            kind: "statements",
            statements: work.statements,
            index: work.index,
            path: nested,
            complete: work.complete,
            skipStatementRedirects: true,
          });
        }, schedule);
        continue;
      }
      if (hasRedirect) {
        schedule({
          kind: "statements",
          ...work,
          path: addOutcome(work.path, indeterminate(statement.span)),
          skipStatementRedirects: true,
        });
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
        if (work.path.nestedScriptDepth + 1 > work.path.state.environment.budgets.nestedScriptDepth) {
          recordPathGap(context, work.path, "max-nested-script-depth", statement.span, work.inPipeline ?? false);
          completeWithDeny(addOutcome(work.path, analysisFailure("max-nested-script-depth", statement.span)));
          break;
        }
        const child = withEnvironment(work.path, pushSubshellFrame(work.path.state.environment), false, work.path.nestedScriptDepth + 1);
        scheduleNested(statement.statements, child, (finished) => continueWork(withEnvironment(
          work.path,
          work.path.state.environment,
          false,
          work.path.nestedScriptDepth,
          finished.outcome,
        )), schedule);
        break;
      }
      case "pipeline":
        schedulePipeline(statement.statements, work.path, continueWork, schedule, statement.span);
        break;
      case "if":
        scheduleIf(statement, work.path, continueWork, schedule);
        break;
      case "time":
        if (statement.body) scheduleChildExecutions([freeze({
          target: freeze({ kind: "statements", statements: freeze([statement.body]) }),
          processEffect: "none",
          environment: work.path.state.environment,
          functionDepth: work.path.functionDepth,
          nestedScriptDepth: work.path.nestedScriptDepth,
          inPipeline: work.inPipeline ?? false,
          isolate: false,
          environmentExplicit: false,
          provenance: work.path.provenance,
        })], work.path, context, completeWithDeny, schedule, statement.span);
        else continueWork(work.path);
        break;
      case "coproc": {
        scheduleChildExecutions([freeze({
          target: freeze({ kind: "statements", statements: freeze([statement.body]) }),
          processEffect: "spawn-async",
          environment: work.path.state.environment,
          functionDepth: work.path.functionDepth,
          nestedScriptDepth: work.path.nestedScriptDepth + 1,
          inPipeline: work.inPipeline ?? false,
          isolate: true,
          environmentExplicit: false,
          provenance: work.path.provenance,
        })], work.path, context, completeWithDeny, schedule, statement.span);
        break;
      }
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
        const tainted = addOutcome(withEnvironment(work.path, taintFrame(work.path.state.environment, { kind: "unsupported-syntax", span: statement.span })), indeterminate(statement.span));
        scheduleNested(statement.statements, tainted, continueWork, schedule);
        break;
      }
    }
  }

  const terminal = denied ?? limitFailure ?? materializeOutcomeSummary(
    mergeOutcomeSummaries(completed.map((result) => result.outcome)),
  );
  const state = completed[0]?.state.environment ?? initial.state.environment;
  return freeze({ kind: "result", state, outcome: terminal, span: programSpan(program) });
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
      const preflightCommand = normalizeCommand(command, input.state.environment, input.sourceDerivedFromBinding);
      const executable = preflightCommand.executable;
      const definitions = executable?.kind === "known" ? input.state.functionCandidates.get(executable.value) : undefined;
      const definitelyFunction = executable?.kind === "known"
        && (definitions?.length ?? 0) > 0
        && !input.state.missingFunctions.has(executable.value);
      if (!definitelyFunction) {
        const preflight = context.preflightCommand(freeze({
          command: preflightCommand,
          span: command.span,
          environment: input.state.environment,
          inPipeline,
          provenance: input.provenance,
        }));
        if (preflight.kind === "deny") {
          recordInvocationEvent(preflightCommand, input, context, command.span, inPipeline);
          completeWithDeny(addOutcome(input, preflight));
          return;
        }
      }
      if (input.nestedScriptDepth + 1 > input.state.environment.budgets.nestedScriptDepth) {
        recordPathGap(context, input, "max-nested-script-depth", command.span, inPipeline);
        completeWithDeny(addOutcome(input, analysisFailure("max-nested-script-depth", command.span)));
        return;
      }
      const child = withEnvironment(input, pushSubshellFrame(input.state.environment), false, input.nestedScriptDepth + 1);
      scheduleNested(retained, child, (finished) => {
        const nested = withEnvironment(
          input,
          input.state.environment,
          false,
          input.nestedScriptDepth,
          finished.outcome,
        );
        if (outcomeSummaryIsDeny(nested.outcome)) {
          completeWithDeny(nested);
          return;
        }
        executeCommand(command, nested, context, complete, completeWithDeny, schedule, false, inPipeline);
      }, schedule);
      return;
    }
  }
  const normalized = normalizeCommand(command, input.state.environment, input.sourceDerivedFromBinding);
  const redirect = analyzeSecretRedirectInvocation(normalized);
  if (redirect.kind === "deny") {
    recordInvocationEvent(normalized, input, context, command.span, inPipeline);
    completeWithDeny(addOutcome(input, policyDeny(command.span, redirect.evidence)));
    return;
  }
  const readonlyAssignment = command.assignments.some((assignment) => lookupBinding(input.state.environment, assignment.name).readonly);
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
    complete(withEnvironment(input, normalized.assignmentPatch.environment, false, input.nestedScriptDepth, input.outcome, appendWrites(input.writes, normalized.assignmentPatch.writes)));
    return;
  }
  if (normalized.executable.kind === "unknown") {
    recordInvocationEvent(normalized, input, context, command.span, inPipeline);
    complete(addOutcome(withEnvironment(input, endCommandOverlay(normalized.environment)), dynamicExecutableIndeterminate(command.span)));
    return;
  }

  const definitions = input.state.functionCandidates.get(normalized.executable.value);
  if (definitions && definitions.length > 0) {
    scheduleFunctionCall(definitions, command, normalized, input, context, complete, schedule, input.state.missingFunctions.has(normalized.executable.value));
    return;
  }

  executeNormalizedInvocation(normalized, input, context, completeWithDeny, schedule, command.span, inPipeline);
}

function executeNormalizedInvocation(
  normalized: NormalizedCommand,
  input: Path,
  context: BashWalkContext,
  completeWithDeny: (path: Path) => void,
  schedule: (work: Work) => void,
  span: SourceSpan,
  inPipeline: boolean,
): void {
  if (!normalized.executable) {
    completeWithDeny(addOutcome(input, indeterminate(span)));
    return;
  }
  if (normalized.executable.kind === "unknown") {
    recordInvocationEvent(normalized, input, context, span, inPipeline);
    completeWithDeny(addOutcome(withEnvironment(input, endCommandOverlay(normalized.environment)), dynamicExecutableIndeterminate(span)));
    return;
  }

  const specialBuiltin = isSpecialBuiltin(normalized.executable.value);
  const builtinEnvironment = specialBuiltin ? persistPrefixAssignments(input.state.environment, normalized) : input.state.environment;
  const builtin = transitionBuiltin(normalized, withShellEnvironment(input.state, builtinEnvironment), span);
  if (builtin.handled) {
    const returnsFromFunction = builtin.returned && input.functionDepth > 0;
    const next = returnsFromFunction
      ? withState(input, builtin.state, true, input.nestedScriptDepth, input.outcome, appendWrites(input.writes, builtin.writes))
      : withState(input, builtin.state, false, input.nestedScriptDepth, input.outcome, appendWrites(input.writes, builtin.writes));
    const transitioned = builtin.outcome ? addOutcome(next, builtin.outcome) : next;
    if (builtin.dispatch) {
      dispatchNormalized(normalized, transitioned, context, completeWithDeny, schedule, span, transitioned.state.environment, inPipeline);
    } else {
      completeWithDeny(transitioned);
    }
    return;
  }

  if (isPossiblyStateMutatingBuiltin(normalized.executable.value)) {
    const tainted = withEnvironment(input, taintFrame(input.state.environment, { kind: "unmodelled-builtin", span }));
    dispatchNormalized(normalized, tainted, context, completeWithDeny, schedule, span, tainted.state.environment, inPipeline);
    return;
  }

  if (isBuiltinShellRoute(normalized)) {
    const tainted = addOutcome(
      withEnvironment(input, taintFrame(input.state.environment, { kind: "builtin-shell-route", span })),
      indeterminate(span),
    );
    dispatchNormalized(normalized, tainted, context, completeWithDeny, schedule, span, tainted.state.environment, inPipeline);
    return;
  }

  dispatchNormalized(normalized, input, context, completeWithDeny, schedule, span, undefined, inPipeline);
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
    environment: input.state.environment,
    functionDepth: input.functionDepth,
    nestedScriptDepth: input.nestedScriptDepth,
    inPipeline,
    provenance: input.provenance,
    processEffect: input.processEffect,
    recordPolicyEvent: context.recordPolicyEvent,
    continueWithSource: (source, environment, options = {}) => freeze({
      outcome: safe(),
      children: Object.freeze([freeze({
        target: freeze({
          kind: "source",
          source,
          dialect: "bash",
          sourceDerivedFromBinding: input.sourceDerivedFromBinding || options.sourceDerivedFromBinding === true,
        }),
        processEffect: options.processEffect ?? "spawn-and-wait",
        environment: environment ?? command.environment,
        functionDepth: input.functionDepth,
        nestedScriptDepth: input.nestedScriptDepth + 1,
        inPipeline,
        isolate: options.isolate ?? true,
        environmentExplicit: environment !== undefined,
        provenance: childProvenance(input.provenance, options),
      })]),
    }),
    continueWithInvocation: (words, environment, options = {}) => {
      const childEnvironment = environment ?? command.environment;
      return freeze({
        outcome: safe(),
        children: Object.freeze([freeze({
          target: freeze({
            kind: "invocation",
            command: normalizedInvocation(words, childEnvironment),
          }),
          processEffect: options.processEffect ?? "exec-replace",
          environment: childEnvironment,
          functionDepth: input.functionDepth,
          nestedScriptDepth: input.nestedScriptDepth,
          inPipeline,
          isolate: options.isolate ?? true,
          environmentExplicit: environment !== undefined,
          provenance: childProvenance(input.provenance, options),
        })]),
      });
    },
    continueWithOpaque: (reason, environment, options = {}) => {
      const childEnvironment = environment ?? command.environment;
      return freeze({
        outcome: safe(),
        children: Object.freeze([freeze({
          target: freeze({ kind: "opaque", reason }),
          processEffect: options.processEffect ?? "unknown",
          environment: childEnvironment,
          functionDepth: input.functionDepth,
          nestedScriptDepth: input.nestedScriptDepth,
          inPipeline,
          isolate: options.isolate ?? true,
          environmentExplicit: environment !== undefined,
          provenance: childProvenance(input.provenance, options),
        })]),
      });
    },
  });
  const result = normalizeDispatchResult(context.dispatchCommand(request));
  const outcome = hasUnknownOperand(command) ? strongestOutcome([result.outcome, indeterminate(span)]) : result.outcome;
  const next = addOutcome(withEnvironment(input, nextEnvironment), outcome);
  scheduleChildExecutions(result.children ?? [], next, context, complete, schedule, span);
}

function scheduleChildExecutions(
  children: readonly BashChildExecution[],
  next: Path,
  context: BashWalkContext,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  span: SourceSpan,
): void {
  if (children.length === 0) {
    complete(next);
    return;
  }

  let remaining = children.length;
  let settled = false;
  const completed: Array<{ readonly path: Path; readonly isolate: boolean }> = [];
  const finishChildren = (): void => {
    if (settled) return;
    settled = true;
    const outcome = mergeOutcomeSummaries(completed.map(({ path }) => path.outcome));
    const state = completeShellState(next.state, completed.map(({ path, isolate }) => ({
      state: path.state,
      writes: path.writes,
      scope: isolate ? "subshell" : "current",
    })));
    complete(withState(next, state, false, next.nestedScriptDepth, outcome));
  };
  for (let index = children.length - 1; index >= 0; index--) {
    const childExecution = children[index]!;
    if (!childExecution.isolate && childExecution.environmentExplicit) {
      completed.push({ path: addOutcome(next, indeterminate(span)), isolate: false });
      remaining--;
      continue;
    }
    if (childExecution.nestedScriptDepth > childExecution.environment.budgets.nestedScriptDepth) {
      context.recordPolicyEvent?.(projectExecutionGapEvent("max-nested-script-depth", {
        environment: childExecution.environment,
        span,
        provenance: childExecution.provenance,
        inPipeline: childExecution.inPipeline,
        processEffect: childExecution.processEffect,
      }));
      completed.push({ path: addOutcome(next, analysisFailure("max-nested-script-depth", span)), isolate: childExecution.isolate });
      remaining--;
      continue;
    }
    const childEnvironment = childExecution.isolate ? pushSubshellFrame(childExecution.environment) : childExecution.environment;
    const child = withSourceBindingProvenance(
      withExecutionProvenance(
        withProcessEffect(resetWrites(withEnvironment(next, childEnvironment, false, childExecution.nestedScriptDepth)), childExecution.processEffect),
        childExecution.provenance,
      ),
      childExecution.target.kind === "source" && childExecution.target.sourceDerivedFromBinding,
    );
    const finishChild = (finished: Path): void => {
      if (settled) return;
      if (outcomeSummaryIsDeny(finished.outcome)) {
        settled = true;
        complete(finished);
        return;
      }
      completed.push({ path: finished, isolate: childExecution.isolate });
      remaining--;
      if (remaining !== 0) return;
      finishChildren();
    };
    switch (childExecution.target.kind) {
      case "invocation":
        schedule({
          kind: "invocation",
          command: childExecution.target.command,
          path: child,
          complete: finishChild,
          span,
          inPipeline: childExecution.inPipeline,
        });
        break;
      case "source": {
        const parsed = parseBashProgram(childExecution.target.source);
        if (parsed.kind === "parse-failure") {
          context.recordPolicyEvent?.(projectExecutionGapEvent("source-parse-failure", {
            environment: childExecution.environment,
            span,
            provenance: childExecution.provenance,
            inPipeline: childExecution.inPipeline,
            processEffect: childExecution.processEffect,
          }));
          scheduleNested(
            parsed.program.statements,
            child,
            (finished) => finishChild(addOutcome(finished, failure(parsed.span))),
            schedule,
            childExecution.inPipeline,
          );
        } else scheduleNested(parsed.statements, child, finishChild, schedule, childExecution.inPipeline);
        break;
      }
      case "statements":
        scheduleNested(childExecution.target.statements, child, finishChild, schedule, childExecution.inPipeline);
        break;
      case "opaque":
        finishChild(addOutcome(
          childExecution.isolate
            ? child
            : withState(child, taintShellState(child.state, { kind: "opaque-current-scope-execution", span })),
          failure(span),
        ));
        break;
    }
  }
  if (remaining === 0) finishChildren();
}

function isPossiblyStateMutatingBuiltin(executable: string): boolean {
  return [
    "alias", "cd", "compgen", "complete", "declare", "dirs", "disown", "enable", "fc", "getopts", "history", "jobs",
    "let", "mapfile", "popd", "printf", "pushd", "readarray", "set", "shift", "trap", "typeset", "ulimit", "umask", "unalias", "wait",
  ].includes(executable);
}

function isBuiltinShellRoute(command: NormalizedCommand): boolean {
  if (command.executable?.kind !== "known" || command.executable.value !== "builtin") return false;
  const target = command.argv[0]?.kind === "known" && command.argv[0].value === "--" ? command.argv[1] : command.argv[0];
  return target?.kind === "known" && ["builtin", "command", "eval", "exec", "source", "."].includes(target.value);
}

function normalizeDispatchResult(result: BashDispatchResult): { readonly outcome: Outcome; readonly children?: readonly BashChildExecution[] } {
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
  context: BashWalkContext,
  complete: (path: Path) => void,
  schedule: (work: Work) => void,
  mayResolveExternally: boolean,
): void {
  if (mayResolveExternally) {
    complete(addOutcome(
      withEnvironment(input, taintFrame(input.state.environment, { kind: "branch-function-absence", span: command.span })),
      indeterminate(command.span),
    ));
  }
  for (let index = definitions.length - 1; index >= 0; index--) {
    const definition = definitions[index]!;
    let frame = pushFunctionFrame(input.state.environment);
    for (const name of normalized.assignmentPatch.writes) {
      frame = assignLocalBinding(frame, name, lookupBinding(normalized.environment, name).value);
      frame = setExported(frame, name, lookupBinding(normalized.environment, name).exported);
    }
    normalized.argv.forEach((argument, argumentIndex) => {
      frame = assignLocalBinding(frame, String(argumentIndex + 1), argument.kind === "known"
        ? known(argument.value)
        : unknown({ kind: argument.reason.kind, span: argument.reason.span }));
    });
    const called = withEnvironment(input, frame, false, input.nestedScriptDepth, input.outcome, input.writes, input.functionDepth + 1);
    if (called.functionDepth > called.state.environment.budgets.functionDepth) {
      recordPathGap(context, called, "max-function-depth", command.span, false);
      complete(addOutcome(called, analysisFailure("max-function-depth", command.span)));
      continue;
    }
    scheduleNested([definition.body], called, (finished) => complete(withEnvironment(
      finished,
      returnFromFunctionFrame(finished.state.environment),
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
  schedule({ kind: "statements", statements, index: 0, path: input, complete, inPipeline });
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
  if (input.nestedScriptDepth + 1 > input.state.environment.budgets.nestedScriptDepth) {
    recordPathGap(context, input, "max-nested-script-depth", span, false);
    complete(addOutcome(input, analysisFailure("max-nested-script-depth", span)));
    return;
  }
  let remaining = statements.length;
  const outcomes: OutcomeSummary[] = [];
  for (let index = statements.length - 1; index >= 0; index--) {
    const child = withEnvironment(input, pushSubshellFrame(input.state.environment), false, input.nestedScriptDepth + 1);
    scheduleNested([statements[index]!], child, (finished) => {
      outcomes.push(finished.outcome);
      remaining--;
      if (remaining === 0) complete(withEnvironment(
        input,
        input.state.environment,
        false,
        input.nestedScriptDepth,
        mergeOutcomeSummaries(outcomes),
      ));
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
  const checkpoint = forkShellState(input.state);
  const zero = resetWrites(addOutcome(input, indeterminate(statement.span)));
  const branches: Path[] = [zero];
  const finish = (branch: Path): void => {
    branches.push(branch);
    if (branches.length !== 3) return;
    const merged = joinShellStates(checkpoint, branches.map((item) => ({ state: item.state, writes: item.writes })));
    complete(withState(
      input,
      merged,
      false,
      input.nestedScriptDepth,
      mergeOutcomeSummaries(branches.map((item) => item.outcome)),
    ));
  };
  const body = resetWrites(addOutcome(withEnvironment(input, taintFrame(input.state.environment, { kind: "unsupported-loop", span: statement.span })), indeterminate(statement.span)));
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
    const checkpoint = forkShellState(condition.state);
    const branches = [statement.consequent, statement.alternate];
    const finished: Path[] = [];
    for (let index = branches.length - 1; index >= 0; index--) {
      scheduleNested(branches[index]!, resetWrites(condition), (branch) => {
        finished.push(branch);
        if (finished.length !== branches.length) return;
        const merged = joinShellStates(checkpoint, finished.map((item) => ({ state: item.state, writes: item.writes })));
        const joined = withState(
          condition,
          merged,
          finished.every((item) => item.returned),
          condition.nestedScriptDepth,
          mergeOutcomeSummaries(finished.map((item) => item.outcome)),
        );
        complete(joined);
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
  state: BashShellState,
  outcome: OutcomeSummary,
  writes: ReadonlySet<string>,
  functionDepth: number,
  nestedScriptDepth: number,
  returned: boolean,
  sourceDerivedFromBinding: boolean,
  provenance: BashExecutionProvenance,
  processEffect: ProcessEffect,
): Path {
  return freeze({
    state,
    outcome,
    writes,
    functionDepth,
    nestedScriptDepth,
    returned,
    sourceDerivedFromBinding,
    provenance,
    processEffect,
  });
}

function withEnvironment(
  input: Path,
  environment: Environment,
  returned = input.returned,
  nestedScriptDepth = input.nestedScriptDepth,
  outcome = input.outcome,
  writes: ReadonlySet<string> = input.writes,
  functionDepth = input.functionDepth,
): Path {
  return withState(input, withShellEnvironment(input.state, environment), returned, nestedScriptDepth, outcome, writes, functionDepth);
}

function withState(
  input: Path,
  state: BashShellState,
  returned = input.returned,
  nestedScriptDepth = input.nestedScriptDepth,
  outcome = input.outcome,
  writes: ReadonlySet<string> = input.writes,
  functionDepth = input.functionDepth,
): Path {
  return path(
    state,
    outcome,
    writes,
    functionDepth,
    nestedScriptDepth,
    returned,
    input.sourceDerivedFromBinding,
    input.provenance,
    input.processEffect,
  );
}

function withFunction(input: Path, definition: BashFunction): Path {
  return withState(input, defineShellFunction(input.state, definition));
}

function resetWrites(input: Path): Path {
  return path(input.state, input.outcome, new Set(), input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding, input.provenance, input.processEffect);
}

function appendWrites(existing: ReadonlySet<string>, next: ReadonlySet<string> | readonly string[]): ReadonlySet<string> {
  return new Set([...existing, ...next]);
}

function addOutcome(input: Path, outcome: Outcome): Path {
  return path(input.state, appendOutcomeSummary(input.outcome, outcome), input.writes, input.functionDepth, input.nestedScriptDepth, input.returned, input.sourceDerivedFromBinding, input.provenance, input.processEffect);
}

function withSourceBindingProvenance(input: Path, sourceDerivedFromBinding: boolean): Path {
  return path(
    input.state,
    input.outcome,
    input.writes,
    input.functionDepth,
    input.nestedScriptDepth,
    input.returned,
    sourceDerivedFromBinding,
    input.provenance,
    input.processEffect,
  );
}

function withExecutionProvenance(input: Path, provenance: BashExecutionProvenance): Path {
  return path(
    input.state,
    input.outcome,
    input.writes,
    input.functionDepth,
    input.nestedScriptDepth,
    input.returned,
    input.sourceDerivedFromBinding,
    provenance,
    input.processEffect,
  );
}

function withProcessEffect(input: Path, processEffect: ProcessEffect): Path {
  return path(
    input.state,
    input.outcome,
    input.writes,
    input.functionDepth,
    input.nestedScriptDepth,
    input.returned,
    input.sourceDerivedFromBinding,
    input.provenance,
    processEffect,
  );
}

function recordInvocationEvent(
  command: NormalizedCommand,
  input: Path,
  context: BashWalkContext,
  span: SourceSpan,
  inPipeline: boolean,
): void {
  const event = projectInvocationEvent(command, {
    environment: command.environment,
    span,
    provenance: input.provenance,
    inPipeline,
    processEffect: input.processEffect,
  });
  if (event) context.recordPolicyEvent?.(event);
}

function recordPathGap(
  context: BashWalkContext,
  path: Path,
  reason: AnalysisBudget,
  span: SourceSpan,
  inPipeline: boolean,
): void {
  context.recordPolicyEvent?.(projectExecutionGapEvent(reason, {
    environment: path.state.environment,
    span,
    provenance: path.provenance,
    inPipeline,
    processEffect: path.processEffect,
  }));
}

function recordWorkGap(
  context: BashWalkContext,
  work: Work,
  reason: AnalysisBudget,
  span: SourceSpan,
): void {
  recordPathGap(context, work.path, reason, span, work.kind === "invocation" ? work.inPipeline : work.inPipeline ?? false);
}

function childProvenance(
  parent: BashExecutionProvenance,
  options: BashChildExecutionOptions,
): BashExecutionProvenance {
  const scriptRoute = options.route === "eval" || options.route === "shell-command";
  const route = [
    ...parent.route,
    ...(options.route ? [options.route] : []),
    ...(scriptRoute && options.sourceDerivedFromBinding ? ["binding-derived-script" as const] : []),
  ];
  return freeze({ route: Object.freeze(route) });
}

function programSpan(program: BashProgram): SourceSpan {
  return Object.freeze({ start: 0, end: program.source.length });
}

function statementSpan(work: Work): SourceSpan | undefined {
  return work.kind === "invocation" ? work.span : work.statements[work.index]?.span;
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

/** Apply the same secret-input rule to redirects owned by compound statements. */
function analyzeStatementSecretRedirects(statement: Exclude<BashStatement, BashCommand>, environment: Environment) {
  if (!("redirects" in statement) || !statement.redirects || statement.redirects.length === 0) return undefined;
  const invocation: NormalizedCommand = {
    executable: null,
    argv: [],
    redirects: statement.redirects.map((redirect) => ({
      kind: redirect.kind,
      target: redirect.target ? expandWord(redirect.target, environment) : null,
    })),
    environment,
    assignmentPatch: { environment, writes: new Set() },
  };
  return analyzeSecretRedirectInvocation(invocation);
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
