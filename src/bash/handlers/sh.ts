import type { CommandHandler } from "../dispatch.js";
import { builtinHandler } from "./command-builtin.js";
import { dotExecutionHandler } from "./command-dot.js";
import { evalHandler } from "./command-eval.js";
import { shellInterpreterHandler, shHandler } from "./command-sh.js";
import { sourceExecutionHandler } from "./command-source.js";

export { shHandler } from "./command-sh.js";

/** Bash-compatible interpreters share the audited `-c` grammar. */
export const shellHandlers: readonly CommandHandler[] = Object.freeze([
  builtinHandler,
  evalHandler,
  sourceExecutionHandler,
  dotExecutionHandler,
  shHandler,
  ...["bash", "dash", "fish", "ksh", "zsh"].map(shellInterpreterHandler),
]);
