import type { CommandHandler } from "../dispatch.js";
import { evalHandler } from "./command-eval.js";
import { shellInterpreterHandler, shHandler } from "./command-sh.js";

export { shHandler } from "./command-sh.js";

/** Bash-compatible interpreters share the audited `-c` grammar. */
export const shellHandlers: readonly CommandHandler[] = Object.freeze([
  evalHandler,
  shHandler,
  ...["bash", "dash", "fish", "ksh", "zsh"].map(shellInterpreterHandler),
]);
