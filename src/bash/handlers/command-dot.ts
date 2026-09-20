import type { CommandHandler } from "../dispatch.js";
import { secretReaderHandler } from "./secret-reader-utils.js";

export const dotHandler = secretReaderHandler(".");
export const dotExecutionHandler: CommandHandler = Object.freeze({
  name: ".",
  handle(_cursor, context) {
    return context.continueWithOpaque("source-file-execution", undefined, {
      isolate: false,
      route: "source",
      processEffect: "none",
    });
  },
});
