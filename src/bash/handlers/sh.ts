import type { CommandHandler } from "../dispatch.js";
import { isBindingResolvedWord } from "../expand.js";
import { assignBinding, known, pushPositionalFrame, unknown } from "../environment.js";
import { indeterminate } from "../outcome.js";

/** Models only the explicit `sh -c SCRIPT` execution boundary. */
export const shHandler: CommandHandler = Object.freeze({
  name: "sh",
  handle(cursor, context) {
    const arguments_ = cursor.invocation.argv;
    let index = 0;
    while (index < arguments_.length) {
      const argument = arguments_[index]!;
      if (argument.kind !== "known") return indeterminate(context.span);
      if (argument.value === "-c" || argument.value === "--command" || isKnownOptionClusterWithCommand(argument.value)) {
        const script = arguments_[index + 1];
        if (!script || script.kind !== "known") return indeterminate(context.span);
        return context.continueWith(script.value, positionalEnvironment(arguments_, index + 2, context), {
          sourceDerivedFromBinding: isBindingResolvedWord(script),
        });
      }
      if (argument.value.startsWith("--command=")) {
        return context.continueWith(argument.value.slice("--command=".length), positionalEnvironment(arguments_, index + 1, context), {
          sourceDerivedFromBinding: isBindingResolvedWord(argument),
        });
      }
      if (isKnownOptionCluster(argument.value)) {
        index++;
        continue;
      }
      if (argument.value === "-o") {
        const option = arguments_[index + 1];
        if (!option || option.kind !== "known") return indeterminate(context.span);
        index += 2;
        continue;
      }
      if (argument.value === "--rcfile" || argument.value === "--init-file") {
        const option = arguments_[index + 1];
        if (!option || option.kind !== "known") return indeterminate(context.span);
        index += 2;
        continue;
      }
      if (["--noprofile", "--norc", "--login", "--posix", "--restricted", "--verbose", "--noediting"].includes(argument.value)) {
        index++;
        continue;
      }
      return indeterminate(context.span);
    }
    return indeterminate(context.span);
  },
});

/** Bash-compatible interpreters share the audited `-c` grammar. */
export const shellHandlers: readonly CommandHandler[] = Object.freeze([
  Object.freeze({
    name: "eval",
    handle(cursor, context) {
      const args = cursor.invocation.argv;
      return args.every((argument) => argument.kind === "known")
        ? context.continueWith(args.map((argument) => argument.value).join(" "), undefined, {
          isolate: false,
          sourceDerivedFromBinding: args.some(isBindingResolvedWord),
        })
        : indeterminate(context.span);
    },
  }),
  shHandler,
  ...["bash", "dash", "fish", "ksh", "zsh"].map((name) => Object.freeze({ ...shHandler, name })),
]);

function isKnownOptionClusterWithCommand(value: string): boolean {
  return isKnownOptionCluster(value) && value.includes("c");
}

function isKnownOptionCluster(value: string): boolean {
  return /^-[abcefhkmnuvx]+$/.test(value);
}

function positionalEnvironment(
  arguments_: readonly import("../expand.js").ResolvedWord[],
  start: number,
  context: Parameters<CommandHandler["handle"]>[1],
) {
  let environment = assignBinding(pushPositionalFrame(context.environment), "0", known("sh"));
  for (let index = start; index < arguments_.length; index++) {
    const argument = arguments_[index]!;
    environment = assignBinding(environment, String(index - start), argument.kind === "known"
      ? known(argument.value)
      : unknown({ kind: "unknown-shell-positional", span: argument.reason.span }));
  }
  return environment;
}
