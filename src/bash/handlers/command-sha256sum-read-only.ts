import type { CommandHandler } from "../dispatch.js";
import { allow, readOnlyHandler } from "./read-only-utils.js";

export const sha256sumReadOnlyHandler: CommandHandler = readOnlyHandler("sha256sum", "generic-read-only", () =>
  allow("generic-read-only", "sha256sum"),
);
