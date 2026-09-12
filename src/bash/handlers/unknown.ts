import type { CommandHandler } from "../dispatch.js";
import { indeterminate } from "../outcome.js";

/** Conservative fallback for unregistered commands: neutral, never allow. */
export const unknownCommandHandler: CommandHandler = Object.freeze({
  name: "unknown-command",
  handle(_cursor, context) {
    return indeterminate(context.span);
  },
});
