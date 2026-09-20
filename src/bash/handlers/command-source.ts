import type { CommandHandler } from "../dispatch.js";
import { secretReaderHandler } from "./secret-reader-utils.js";

export const sourceHandler = secretReaderHandler("source");
export const sourceExecutionHandler: CommandHandler = Object.freeze({
  name: "source",
  handle(_cursor, context) {
    return context.continueWithOpaque("source-file-execution", undefined, {
      isolate: false,
      route: "source",
      processEffect: "none",
    });
  },
});
