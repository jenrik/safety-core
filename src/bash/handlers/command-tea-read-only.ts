import type { CommandHandler } from "../dispatch.js";
import { allow, defer, readOnlyHandler } from "./read-only-utils.js";

export const teaReadOnlyHandler: CommandHandler = readOnlyHandler("tea", "generic-read-only", (args) =>
  args.length === 1 && args[0] === "--help"
    ? allow("generic-read-only", "tea")
    : defer("generic-read-only", "tea"),
);
