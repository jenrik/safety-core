import type { CommandHandler } from "../dispatch.js";
import { STRICT_READ_ONLY_COMMANDS } from "../policies/read-only.js";
import { gitReadOnlyHandler } from "./command-git-read-only.js";
import { ghReadOnlyHandler } from "./command-gh-read-only.js";
import { helmReadOnlyHandler } from "./command-helm-read-only.js";
import { sha256sumReadOnlyHandler } from "./command-sha256sum-read-only.js";
import { straceReadOnlyHandler } from "./command-strace-read-only.js";
import { strictReadOnlyHandler } from "./command-strict-read-only.js";
import { teaReadOnlyHandler } from "./command-tea-read-only.js";

export const readOnlyHandlers: readonly CommandHandler[] = Object.freeze([
  straceReadOnlyHandler,
  teaReadOnlyHandler,
  gitReadOnlyHandler,
  sha256sumReadOnlyHandler,
  ghReadOnlyHandler,
  helmReadOnlyHandler,
  ...Object.keys(STRICT_READ_ONLY_COMMANDS).map(strictReadOnlyHandler),
]);

export const ghReadOnlyHandlers: readonly CommandHandler[] = Object.freeze([straceReadOnlyHandler, ghReadOnlyHandler]);
export const helmReadOnlyHandlers: readonly CommandHandler[] = Object.freeze([straceReadOnlyHandler, helmReadOnlyHandler]);
export const genericReadOnlyHandlers: readonly CommandHandler[] = Object.freeze([
  straceReadOnlyHandler,
  teaReadOnlyHandler,
  gitReadOnlyHandler,
  sha256sumReadOnlyHandler,
]);
export function strictReadOnlyHandlers(executable: string): readonly CommandHandler[] {
  return STRICT_READ_ONLY_COMMANDS[executable]
    ? Object.freeze([straceReadOnlyHandler, strictReadOnlyHandler(executable)])
    : Object.freeze([]);
}
