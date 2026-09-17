import type { CommandHandler } from "../dispatch.js";
import { dynamicExecutableIndeterminate, indeterminate } from "../outcome.js";

const SCRIPT_INTERPRETER = /^(?:bun|deno|node|perl|php|python(?:\d+(?:\.\d+)*)?|ruby|ts-node|tsx)$/;

/** Conservative fallback for unregistered commands: neutral, never allow. */
export const unknownCommandHandler: CommandHandler = Object.freeze({
  name: "unknown-command",
  handle(cursor, context) {
    const executable = cursor.invocation.executable;
    return executable?.kind === "known" && (executable.value.includes("/") || SCRIPT_INTERPRETER.test(executable.value))
      ? dynamicExecutableIndeterminate(context.span)
      : indeterminate(context.span);
  },
});
