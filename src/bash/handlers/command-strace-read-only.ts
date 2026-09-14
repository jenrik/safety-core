import type { CommandHandler } from "../dispatch.js";
import { readOnlyStraceOutcome } from "./read-only-utils.js";

/** strace is transparent unless its trace-output options would create a file. */
export const straceReadOnlyHandler: CommandHandler = Object.freeze({
  name: "strace",
  handle(cursor, context) {
    return readOnlyStraceOutcome(cursor, context.span);
  },
});
