import type { CommandHandler } from "../dispatch.js";
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
      if (argument.value === "-c" || isKnownOptionClusterWithCommand(argument.value)) {
        const script = arguments_[index + 1];
        if (!script || script.kind !== "known") return indeterminate(context.span);
        return context.continueWith(script.value);
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
      return indeterminate(context.span);
    }
    return indeterminate(context.span);
  },
});

/** Bash-compatible interpreters share the audited `-c` grammar. */
export const shellHandlers: readonly CommandHandler[] = Object.freeze([
  shHandler,
  ...["bash", "dash", "fish", "ksh", "zsh"].map((name) => Object.freeze({ ...shHandler, name })),
]);

function isKnownOptionClusterWithCommand(value: string): boolean {
  return isKnownOptionCluster(value) && value.includes("c");
}

function isKnownOptionCluster(value: string): boolean {
  return /^-[abcefhkmnuvx]+$/.test(value);
}
