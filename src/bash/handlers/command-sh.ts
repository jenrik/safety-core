import { continuePreflight, type CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { assignBinding, hasBinding, known, lookupBinding, pushPositionalFrame, unknown } from "../environment.js";
import { dynamicExecutableIndeterminate, indeterminate, policyDeny, strongestOutcome, type Outcome } from "../outcome.js";
import { scanOptions, type OptionGrammar } from "../options.js";
import type { BashDispatchResult } from "../walker.js";
import { basename } from "../../shell.js";
import { isSecretPath } from "../../secrets.js";
import { taintWrapperResult } from "./wrapper-utils.js";

/** Models only the explicit `sh -c SCRIPT` execution boundary. */
export const shHandler: CommandHandler = Object.freeze({
  name: "sh",
  handle(cursor, context) {
    return handleShell("sh", cursor, context);
  },
});

function handleShell(name: string, cursor: Parameters<CommandHandler["handle"]>[0], context: Parameters<CommandHandler["handle"]>[1]) {
  const startup = { detected: false };
  const result = handleShellArguments(name, cursor, context, startup);
  return startup.detected ? appendStartupExecution(result, context) : result;
}

function handleShellArguments(
  name: string,
  cursor: Parameters<CommandHandler["handle"]>[0],
  context: Parameters<CommandHandler["handle"]>[1],
  startup: { detected: boolean },
) {
  const arguments_ = cursor.invocation.argv;
  const parsed = scanOptions(arguments_, shellOptionGrammar(name));
  if (parsed.kind === "failure") {
    const inherited = shellStartupEnvironmentRoute(name, cursor, context, []);
    return typeof inherited === "boolean" ? dynamicExecutableIndeterminate(context.span) : inherited;
  }
  if (parsed.terminal?.id === "informational") return indeterminate(context.span);
  const initOptions = parsed.options.filter((option) => option.id === "init-command");
  const initCommands = initOptions.flatMap((option) => option.value?.kind === "known" ? [option.value.value] : []);
  for (const option of parsed.options) {
    if (option.id !== "startup-file") continue;
    startup.detected = true;
    if (option.value?.kind !== "known") return dynamicExecutableIndeterminate(context.span);
    if (isSecretPath(option.value.value)) return secretScriptDeny(name, option.value.value, context);
  }
  const inheritedStartup = shellStartupEnvironmentRoute(name, cursor, context, parsed.options);
  if (typeof inheritedStartup !== "boolean") return inheritedStartup;
  startup.detected ||= inheritedStartup;
  if (shellInvocationMayReadStartup(name, parsed.options)) startup.detected = true;
  if (initOptions.some((option) => option.value?.kind !== "known")) return dynamicShellCommandTarget(name, context);
  if (parsed.terminal) {
    const script = parsed.terminal.value;
    if (!script || script.kind !== "known") return dynamicShellCommandTarget(name, context);
    const original = arguments_[parsed.terminal.index]!;
    return shellCommandTarget(
      name,
      [...initCommands, script.value].join(";\n"),
      positionalEnvironment(arguments_, parsed.operandIndex, context),
      isBindingResolvedWord(parsed.terminal.attached ? original : script),
      context,
    );
  }
  const operand = arguments_[parsed.operandIndex];
  if (operand?.kind === "known" && isSecretPath(operand.value)) return secretScriptDeny(name, operand.value, context);
  return initCommands.length > 0
    ? shellCommandTarget(name, initCommands.join(";\n"), undefined, false, context)
    : dynamicExecutableIndeterminate(context.span);
}

function dynamicShellCommandTarget(
  name: string,
  context: Parameters<CommandHandler["handle"]>[1],
): BashDispatchResult {
  if (name === "fish") return unsupportedFishSource(context);
  return context.continueWithOpaque("unsupported-execution", undefined, {
    isolate: true,
    route: "shell-command",
    processEffect: "spawn-and-wait",
  });
}

function shellOptionGrammar(name: string): OptionGrammar {
  if (name === "fish") return FISH_OPTIONS;
  if (name === "zsh") return ZSH_OPTIONS;
  if (name === "bash") return BASH_OPTIONS;
  return POSIX_SHELL_OPTIONS;
}

function shellInvocationMayReadStartup(name: string, options: readonly { readonly id: string }[]): boolean {
  const ids = new Set(options.map((option) => option.id));
  // zsh always reads its installation-global zshenv before RCS can suppress later files.
  if (name === "zsh") return true;
  // fish reads configuration before command source unless --no-config is present.
  if (name === "fish") return !ids.has("no-config");
  // Keep unreviewed sh-family interactive/login startup conservative.
  if (["sh", "dash", "ksh"].includes(name)) return ids.has("interactive") || ids.has("login");
  if (name !== "bash") return false;

  const loginStartup = ids.has("login") && !ids.has("no-profile");
  const interactiveStartup = ids.has("interactive") && !ids.has("login") && !ids.has("no-rc");
  return loginStartup || interactiveStartup;
}

function shellCommandTarget(
  name: string,
  source: string,
  environment: Parameters<CommandHandler["handle"]>[1]["environment"] | undefined,
  sourceDerivedFromBinding: boolean,
  context: Parameters<CommandHandler["handle"]>[1],
): BashDispatchResult {
  if (name === "fish") {
    return unsupportedFishSource(context);
  }
  // TODO: zsh is parsed as a best-effort Bash alias; replace this with a matching parser.
  const result = context.continueWithSource(source, environment, {
      route: "shell-command",
      sourceDerivedFromBinding,
      processEffect: "spawn-and-wait",
    });
  return taintWrapperResult(result, context);
}

function unsupportedFishSource(context: Parameters<CommandHandler["handle"]>[1] | Parameters<NonNullable<CommandHandler["preflight"]>>[1]) {
  // TODO: Replace this block with a dedicated fish parser and equivalence contract.
  const outcome = policyDeny(context.span, Object.freeze({
    name: "unsupported-shell-source",
    decision: "deny" as const,
    reason: "fish command source is blocked until dedicated parser support is available",
  }));
  if (!("continueWithOpaque" in context)) return outcome;
  const opaque = context.continueWithOpaque("unsupported-shell-source", undefined, {
    isolate: true,
    route: "shell-command",
    processEffect: "spawn-and-wait",
  });
  return "kind" in opaque ? outcome : Object.freeze({ outcome, children: opaque.children });
}

function shellStartupEnvironmentRoute(
  name: string,
  cursor: Parameters<CommandHandler["handle"]>[0],
  context: Parameters<CommandHandler["handle"]>[1],
  options: readonly { readonly id: string }[],
): boolean | Outcome {
  const ids = new Set(options.map((option) => option.id));
  const names = name === "bash"
    ? ids.has("interactive")
      ? ids.has("posix") ? ["ENV"] : []
      : ["BASH_ENV"]
    : ["sh", "dash", "ksh"].includes(name)
      ? ["ENV"]
      : name === "zsh" ? ["ZDOTDIR"] : [];
  for (const environmentName of names) {
    const environment = cursor.invocation.environment;
    if (!hasBinding(environment, environmentName)) {
      if (environment.missingBindings === "unknown") return true;
      continue;
    }
    const value = lookupBinding(environment, environmentName).value;
    if (value.kind === "unknown") return true;
    if (value.kind !== "known" || value.value.length === 0) continue;
    if (isSecretPath(value.value)) return secretScriptDeny(name, value.value, context);
    return true;
  }
  return false;
}

function appendStartupExecution(result: BashDispatchResult, context: Parameters<CommandHandler["handle"]>[1]): BashDispatchResult {
  const startup = context.continueWithOpaque("shell-startup-execution", undefined, {
    isolate: true,
    route: "shell-startup",
    processEffect: "spawn-and-wait",
  });
  const outcome = strongestOutcome([
    "kind" in result ? result : result.outcome,
    "kind" in startup ? startup : startup.outcome,
  ]);
  const children = Object.freeze([
    ...("kind" in startup ? [] : startup.children ?? []),
    ...("kind" in result ? [] : result.children ?? []),
  ]);
  return children.length === 0 ? outcome : Object.freeze({ outcome, children });
}

function secretScriptDeny(name: string, path: string, context: Parameters<CommandHandler["handle"]>[1]) {
  return policyDeny(context.span, Object.freeze({
    name: "secret-read",
    decision: "deny" as const,
    reason: `bash \`${name}\` on '${basename(path)}'`,
  }));
}

/** Bash-compatible interpreters share the audited `-c` grammar. */
export function shellInterpreterHandler(name: string): CommandHandler {
  return Object.freeze({
    name,
    ...(name === "fish" ? {
      preflight(cursor: Parameters<NonNullable<CommandHandler["preflight"]>>[0], context: Parameters<NonNullable<CommandHandler["preflight"]>>[1]) {
        const parsed = scanOptions(cursor.invocation.argv, FISH_OPTIONS);
        if (parsed.kind === "parsed"
          && (parsed.terminal?.id === "command" || parsed.options.some((option) => option.id === "init-command"))) {
          return unsupportedFishSource(context);
        }
        return continuePreflight();
      },
    } : {}),
    handle(cursor, context) {
      return handleShell(name, cursor, context);
    },
  });
}

const BASH_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  shortPrefixes: Object.freeze(["-", "+"]),
  options: Object.freeze([
    Object.freeze({ id: "command", short: Object.freeze(["c"]), shortPrefixes: Object.freeze(["-"]), value: "required", terminal: "deferred" }),
    Object.freeze({ id: "command", long: Object.freeze(["--command"]), value: "required", equals: true, terminal: "immediate" }),
    Object.freeze({ id: "named-option", short: Object.freeze(["o", "O"]), value: "required", attached: true }),
    Object.freeze({ id: "interactive", short: Object.freeze(["i"]), shortPrefixes: Object.freeze(["-"]), value: "none" }),
    Object.freeze({ id: "login", short: Object.freeze(["l"]), shortPrefixes: Object.freeze(["-"]), long: Object.freeze(["--login"]), value: "none" }),
    Object.freeze({ id: "no-profile", long: Object.freeze(["--noprofile"]), value: "none" }),
    Object.freeze({ id: "no-rc", long: Object.freeze(["--norc"]), value: "none" }),
    Object.freeze({ id: "flag", short: Object.freeze([..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"].filter((option) => !["c", "i", "l", "o", "O"].includes(option))), value: "none" }),
    Object.freeze({ id: "startup-file", long: Object.freeze(["--rcfile", "--init-file"]), value: "required", equals: true }),
    Object.freeze({
      id: "flag",
      long: Object.freeze([
        "--debug", "--debugger", "--noediting", "--pretty-print",
        "--restricted", "--verbose",
      ]),
      value: "none",
    }),
    Object.freeze({ id: "posix", long: Object.freeze(["--posix"]), value: "none" }),
  ]),
});

const POSIX_SHELL_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  shortPrefixes: Object.freeze(["-", "+"]),
  options: Object.freeze([
    Object.freeze({ id: "command", short: Object.freeze(["c"]), shortPrefixes: Object.freeze(["-"]), value: "required", terminal: "deferred" }),
    Object.freeze({ id: "named-option", short: Object.freeze(["o", "O"]), value: "required", attached: true }),
    Object.freeze({ id: "interactive", short: Object.freeze(["i"]), shortPrefixes: Object.freeze(["-"]), value: "none" }),
    Object.freeze({ id: "login", short: Object.freeze(["l"]), shortPrefixes: Object.freeze(["-"]), value: "none" }),
    Object.freeze({ id: "flag", short: Object.freeze([..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"].filter((option) => !["c", "i", "l", "o", "O"].includes(option))), value: "none" }),
  ]),
});

const ZSH_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  shortPrefixes: Object.freeze(["-", "+"]),
  options: Object.freeze([
    Object.freeze({ id: "command", short: Object.freeze(["c"]), shortPrefixes: Object.freeze(["-"]), value: "required", terminal: "deferred" }),
    Object.freeze({ id: "command", long: Object.freeze(["--command"]), value: "required", equals: true, terminal: "immediate" }),
    Object.freeze({ id: "named-option", short: Object.freeze(["o", "O"]), value: "required", attached: true }),
    Object.freeze({ id: "interactive", short: Object.freeze(["i"]), shortPrefixes: Object.freeze(["-"]), exact: Object.freeze(["--interactive"]), value: "none" }),
    Object.freeze({ id: "login", short: Object.freeze(["l"]), shortPrefixes: Object.freeze(["-"]), exact: Object.freeze(["--login"]), value: "none" }),
    Object.freeze({ id: "no-rcs", short: Object.freeze(["f"]), shortPrefixes: Object.freeze(["-"]), exact: Object.freeze(["--no-rcs", "--no_rcs", "+-RCS", "+-no-RCS"]), value: "none" }),
    Object.freeze({ id: "no-global-rcs", exact: Object.freeze(["--no-global-rcs"]), value: "none" }),
    Object.freeze({ id: "rcs", exact: Object.freeze(["--rcs", "--GLOBAL_RCS", "--global-rcs"]), value: "none" }),
    Object.freeze({ id: "informational", exact: Object.freeze(["--help", "--version"]), value: "none", terminal: "immediate" }),
    Object.freeze({ id: "flag", short: Object.freeze([..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"].filter((option) => !["c", "f", "i", "l", "o", "O"].includes(option))), value: "none" }),
  ]),
});

const FISH_OPTIONS: OptionGrammar = Object.freeze({
  longResolution: "exact",
  options: Object.freeze([
    Object.freeze({ id: "command", short: Object.freeze(["c"]), long: Object.freeze(["--command"]), value: "required", attached: true, equals: true, terminal: "immediate" }),
    Object.freeze({ id: "init-command", short: Object.freeze(["C"]), long: Object.freeze(["--init-command", "--init-cmd"]), value: "required", attached: true, equals: true }),
    Object.freeze({ id: "value", short: Object.freeze(["d", "f", "p", "o"]), long: Object.freeze(["--debug", "--features", "--profile", "--profile-startup", "--debug-output"]), value: "required", attached: true, equals: true }),
    Object.freeze({ id: "interactive", short: Object.freeze(["i"]), long: Object.freeze(["--interactive"]), value: "none" }),
    Object.freeze({ id: "login", short: Object.freeze(["l"]), long: Object.freeze(["--login"]), value: "none" }),
    Object.freeze({ id: "no-config", short: Object.freeze(["N"]), long: Object.freeze(["--no-config"]), value: "none" }),
    Object.freeze({ id: "informational", short: Object.freeze(["v"]), long: Object.freeze(["--version", "--print-debug-categories"]), value: "none", terminal: "immediate" }),
    Object.freeze({ id: "flag", short: Object.freeze(["P"]), long: Object.freeze(["--private", "--print-rusage-self"]), value: "none" }),
  ]),
});

function positionalEnvironment(arguments_: readonly ResolvedWord[], start: number, context: Parameters<CommandHandler["handle"]>[1]) {
  let environment = assignBinding(pushPositionalFrame(context.environment), "0", known("sh"));
  for (let index = start; index < arguments_.length; index++) {
    const argument = arguments_[index]!;
    environment = assignBinding(environment, String(index - start), argument.kind === "known"
      ? known(argument.value)
      : unknown({ kind: "unknown-shell-positional", span: argument.reason.span }));
  }
  return environment;
}
