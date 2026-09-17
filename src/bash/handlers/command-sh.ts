import type { CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord, type ResolvedWord } from "../expand.js";
import { assignBinding, known, pushPositionalFrame, unknown } from "../environment.js";
import { indeterminate, policyDeny } from "../outcome.js";
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
    const arguments_ = cursor.invocation.argv;
    let index = 0;
    const initCommands: string[] = [];
    while (index < arguments_.length) {
      const argument = arguments_[index]!;
      if (argument.kind !== "known") return indeterminate(context.span);
      if (argument.value === "--") {
        const script = arguments_[index + 1];
        return script?.kind === "known" && isSecretPath(script.value)
          ? secretScriptDeny(name, script.value, context)
          : indeterminate(context.span);
      }
      if (name === "fish" && (argument.value === "-C" || argument.value === "--init-command")) {
        const command = arguments_[index + 1];
        if (!command || command.kind !== "known") return indeterminate(context.span);
        initCommands.push(command.value);
        index += 2;
        continue;
      }
      if (name === "fish" && argument.value === "--init-cmd") {
        const command = arguments_[index + 1];
        if (!command || command.kind !== "known") return indeterminate(context.span);
        initCommands.push(command.value);
        index += 2;
        continue;
      }
      if (name === "fish" && (argument.value.startsWith("-C") || argument.value.startsWith("--init-command=") || argument.value.startsWith("--init-cmd="))) {
        initCommands.push(argument.value.startsWith("-C")
          ? argument.value.slice(2)
          : argument.value.slice(argument.value.indexOf("=") + 1));
        index++;
        continue;
      }
      if (name === "fish" && ["-d", "-f", "-p", "-o", "--debug", "--features", "--profile", "--profile-startup", "--debug-output"].includes(argument.value)) {
        if (arguments_[index + 1]?.kind !== "known") return indeterminate(context.span);
        index += 2;
        continue;
      }
      if (name === "fish" && (/^-[dfpo].+/.test(argument.value)
        || ["--debug=", "--features=", "--profile=", "--profile-startup=", "--debug-output="].some((option) => argument.value.startsWith(option)))) {
        index++;
        continue;
      }
      if (name === "fish" && ["--interactive", "--login", "--no-config", "--private", "--print-rusage-self"].includes(argument.value)) {
        index++;
        continue;
      }
      if (name === "fish") {
        const fishShort = fishShortOptionCount(argument.value, arguments_[index + 1]);
        if (fishShort) {
          index += fishShort;
          continue;
        }
      }
      if (name === "zsh" && /^(?:--|\+-)(?:no[-_])?[A-Za-z][A-Za-z0-9_-]*$/.test(argument.value)) {
        if (argument.value === "--help" || argument.value === "--version") return indeterminate(context.span);
        index++;
        continue;
      }
      const cluster = shellOptionCluster(argument.value);
      if (argument.value === "--command" || cluster?.hasCommand) {
        const scriptIndex = index + 1 + (cluster?.namedOptionCount ?? 0);
        for (let optionIndex = index + 1; optionIndex < scriptIndex; optionIndex++) {
          if (arguments_[optionIndex]?.kind !== "known") return indeterminate(context.span);
        }
        const script = arguments_[scriptIndex];
        if (!script || script.kind !== "known") return indeterminate(context.span);
        return taintWrapperResult(context.continueWith([...initCommands, script.value].join(";\n"), positionalEnvironment(arguments_, scriptIndex + 1, context), {
          route: "shell-command",
          sourceDerivedFromBinding: isBindingResolvedWord(script),
        }), context);
      }
      if (argument.value.startsWith("--command=")) {
        return taintWrapperResult(context.continueWith([...initCommands, argument.value.slice("--command=".length)].join(";\n"), positionalEnvironment(arguments_, index + 1, context), {
          route: "shell-command",
          sourceDerivedFromBinding: isBindingResolvedWord(argument),
        }), context);
      }
      if (cluster) {
        for (let offset = 1; offset <= cluster.namedOptionCount; offset++) {
          if (arguments_[index + offset]?.kind !== "known") return indeterminate(context.span);
        }
        index += 1 + cluster.namedOptionCount;
        continue;
      }
      if (argument.value === "--rcfile" || argument.value === "--init-file") {
        const option = arguments_[index + 1];
        if (!option || option.kind !== "known") return indeterminate(context.span);
        index += 2;
        continue;
      }
      if (argument.value.startsWith("--rcfile=") || argument.value.startsWith("--init-file=")) {
        index++;
        continue;
      }
      if ([
        "--debug", "--debugger", "--login", "--noediting", "--noprofile", "--norc", "--posix", "--pretty-print",
        "--restricted", "--verbose",
      ].includes(argument.value)) {
        index++;
        continue;
      }
      return isSecretPath(argument.value) ? secretScriptDeny(name, argument.value, context) : indeterminate(context.span);
    }
    return initCommands.length > 0
      ? taintWrapperResult(context.continueWith(initCommands.join(";\n"), undefined, { route: "shell-command" }), context)
      : indeterminate(context.span);
}

function secretScriptDeny(name: string, path: string, context: Parameters<CommandHandler["handle"]>[1]) {
  return policyDeny(context.span, Object.freeze({
    name: "secret-read",
    decision: "deny" as const,
    reason: `bash \`${name}\` on '${basename(path)}'`,
  }));
}

function fishShortOptionCount(value: string, next: ResolvedWord | undefined): 1 | 2 | undefined {
  if (!value.startsWith("-") || value.startsWith("--") || value.length < 3) return undefined;
  const options = value.slice(1);
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (["i", "l", "N", "P", "v"].includes(option)) continue;
    if (!["d", "f", "p", "o"].includes(option)) return undefined;
    return options.slice(index + 1).length > 0 ? 1 : next?.kind === "known" ? 2 : undefined;
  }
  return undefined;
}

/** Bash-compatible interpreters share the audited `-c` grammar. */
export function shellInterpreterHandler(name: string): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor, context) {
      return handleShell(name, cursor, context);
    },
  });
}

function shellOptionCluster(value: string): { readonly hasCommand: boolean; readonly namedOptionCount: number } | undefined {
  if (!/^[+-][A-Za-z]+$/.test(value)) return undefined;
  return Object.freeze({
    hasCommand: value.startsWith("-") && value.includes("c"),
    namedOptionCount: [...value].filter((option) => option === "o" || option === "O").length,
  });
}

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
