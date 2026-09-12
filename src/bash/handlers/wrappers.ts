import type { CommandHandler, DispatchContext, InvocationCursor } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { assignBinding, fromInitialEnvironment, known as knownBinding, setExported, unsetBinding } from "../environment.js";
import { indeterminate, safe, strongestOutcome, type Outcome } from "../outcome.js";
import type { BashDispatchContinuation, BashDispatchResult } from "../walker.js";

type WrapperParser = (arguments_: readonly ResolvedWord[], context: DispatchContext) => BashDispatchResult;

/** Transparent command wrappers. Each parser owns only its documented grammar. */
export const wrapperHandlers: readonly CommandHandler[] = Object.freeze([
  handler("env", parseEnv),
  handler("command", parseCommand),
  handler("doas", parseDoas),
  handler("exec", parseExec),
  handler("nice", parseNice),
  handler("nohup", parseNohup),
  handler("setsid", parseSetsid),
  handler("stdbuf", parseStdbuf),
  handler("timeout", parseTimeout),
  handler("strace", parseStrace),
  handler("xargs", parseXargs),
  handler("find", parseFind),
]);

function handler(name: string, parse: WrapperParser): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor: InvocationCursor, context: DispatchContext): BashDispatchResult {
      return parse(cursor.invocation.argv, context);
    },
  });
}

function parseEnv(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  let index = 0;
  let environment = context.environment;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context, environment);
    if (argument === "-i" || argument === "--ignore-environment") {
      environment = fromInitialEnvironment({}, environment.budgets, "unset");
      index++;
      continue;
    }
    if (argument === "-u" || argument === "--unset") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      environment = unsetBinding(environment, arguments_[index + 1]!.value);
      index += 2;
      continue;
    }
    if (argument === "-C" || argument === "--chdir") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument.startsWith("--unset=")) {
      environment = unsetBinding(environment, argument.slice("--unset=".length));
      index++;
      continue;
    }
    if (argument.startsWith("--chdir=")) {
      index++;
      continue;
    }
    const assigned = assignment(argument);
    if (assigned) {
      environment = setExported(assignBinding(environment, assigned.name, knownBinding(assigned.value)), assigned.name, true);
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context, environment);
  }
  return indeterminate(context.span);
}

function parseCommand(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (argument === "-p") {
      index++;
      continue;
    }
    if (argument === "-v" || argument === "-V") return safe();
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}

function parseDoas(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  return parseOptionChild(arguments_, context, new Map([["-u", 1], ["-C", 1]]), new Set(["-n", "-s", "--"]));
}

function parseExec(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (argument === "-a") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument === "-c" || argument === "-l") {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}

function parseNice(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  return parseOptionChild(
    arguments_,
    context,
    new Map([["-n", 1], ["--adjustment", 1]]),
    new Set(["--"]),
    ["-n", "--adjustment="],
  );
}

function parseNohup(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  return parseOptionChild(arguments_, context, new Map(), new Set(["--"]));
}

function parseSetsid(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  return parseOptionChild(arguments_, context, new Map(), new Set(["-c", "--ctty", "-f", "--fork", "-w", "--wait", "--"]));
}

function parseStdbuf(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  return parseOptionChild(
    arguments_,
    context,
    new Map([["-i", 1], ["-o", 1], ["-e", 1]]),
    new Set(["--"]),
    ["--input=", "--output=", "--error=", "-i", "-o", "-e"],
  );
}

function parseTimeout(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return durationThenChild(arguments_, index + 1, context);
    if (argument === "-k" || argument === "--kill-after" || argument === "-s" || argument === "--signal") {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (argument.startsWith("--kill-after=") || argument.startsWith("--signal=") || argument === "--foreground" || argument === "--preserve-status") {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index + 1, context);
  }
  return indeterminate(context.span);
}

function durationThenChild(arguments_: readonly ResolvedWord[], index: number, context: DispatchContext): BashDispatchResult {
  if (!isKnown(arguments_[index])) return indeterminate(context.span);
  return continueFrom(arguments_, index + 1, context);
}

function parseStrace(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  const valueOptions = new Set(["-e", "-o", "-p", "-P", "-s", "-u", "-E", "-a"]);
  const flags = new Set(["-f", "-ff", "-c", "-C", "-D", "-dd", "-ddd", "-h", "-q", "-qq", "-r", "-t", "-tt", "-ttt", "-T", "-v", "-V", "-x", "-xx"]);
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    if (valueOptions.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (flags.has(argument) || /^-(?:e|o|p|P|s|u|E|a).+/.test(argument)) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}

/** xargs supplies runtime stdin items, so even static templates are not closed child invocations. */
function parseXargs(arguments_: readonly ResolvedWord[], context: DispatchContext): Outcome {
  return arguments_.every((argument) => argument.kind === "known") ? indeterminate(context.span) : indeterminate(context.span);
}

function parseFind(arguments_: readonly ResolvedWord[], context: DispatchContext): BashDispatchResult {
  const continuations: BashDispatchContinuation[] = [];
  const outcomes: Outcome[] = [];
  let foundAction = false;
  for (let index = 0; index < arguments_.length; index++) {
    const current = arguments_[index]!;
    if (current.kind !== "known") {
      outcomes.push(indeterminate(context.span));
      continue;
    }
    const argument = current.value;
    if (argument !== "-exec" && argument !== "-execdir") continue;

    foundAction = true;
    const end = findTerminator(arguments_, index + 1, context);
    if (end === undefined) return indeterminate(context.span);
    const child = arguments_.slice(index + 1, end);
    if (child.length === 0 || child.some((word) => word.kind !== "known" || word.value === "{}")) {
      outcomes.push(indeterminate(context.span));
      index = end;
      continue;
    }
    const result = continueFrom(child, 0, context);
    if ("kind" in result) outcomes.push(result);
    else {
      outcomes.push(result.outcome);
      if (result.continuations) continuations.push(...result.continuations);
    }
    index = end;
  }
  if (!foundAction) return indeterminate(context.span);
  const outcome = strongestOutcome(outcomes);
  return continuations.length === 0 ? outcome : { outcome, continuations: Object.freeze(continuations) };
}

function findTerminator(arguments_: readonly ResolvedWord[], start: number, _context: DispatchContext): number | undefined {
  for (let index = start; index < arguments_.length; index++) {
    const argument = arguments_[index]!;
    if (argument.kind === "known" && (argument.value === ";" || argument.value === "+")) return index;
  }
  return undefined;
}

function parseOptionChild(
  arguments_: readonly ResolvedWord[],
  context: DispatchContext,
  valueOptions: ReadonlyMap<string, number>,
  flags: ReadonlySet<string>,
  equalsOptions: readonly string[] = [],
): BashDispatchResult {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return continueFrom(arguments_, index + 1, context);
    const arity = valueOptions.get(argument);
    if (arity !== undefined) {
      for (let offset = 1; offset <= arity; offset++) if (!isKnown(arguments_[index + offset])) return indeterminate(context.span);
      index += arity + 1;
      continue;
    }
    if (flags.has(argument) || equalsOptions.some((prefix) => argument.startsWith(prefix))) {
      index++;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return continueFrom(arguments_, index, context);
  }
  return indeterminate(context.span);
}

function continueFrom(
  arguments_: readonly ResolvedWord[],
  index: number,
  context: DispatchContext,
  environment?: DispatchContext["environment"],
): BashDispatchResult {
  const child = arguments_.slice(index);
  if (child.length === 0 || child.some((argument) => argument.kind !== "known")) return indeterminate(context.span);
  return context.continueWith(child.map((argument) => quote(argument.value)).join(" "), environment, {
    sourceDerivedFromBinding: child.some(isBindingResolvedWord),
  });
}

function known(argument: ResolvedWord | undefined, context: DispatchContext): string | Outcome {
  return argument?.kind === "known" ? argument.value : indeterminate(context.span);
}

function isKnown(argument: ResolvedWord | undefined): argument is Extract<ResolvedWord, { readonly kind: "known" }> {
  return argument?.kind === "known";
}

function assignment(value: string): { readonly name: string; readonly value: string } | undefined {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s.exec(value);
  return match ? { name: match[1]!, value: match[2]! } : undefined;
}

function quote(value: string): string {
  return `'${value.replaceAll("'", "'\\\"'\\\"'")}'`;
}
