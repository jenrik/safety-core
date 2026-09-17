import type { CommandHandler } from "../dispatch.js";
import { commandHandler } from "./command-command.js";
import { doasHandler } from "./command-doas.js";
import { envHandler } from "./command-env.js";
import { execHandler } from "./command-exec.js";
import { findHandler } from "./command-find.js";
import { niceHandler } from "./command-nice.js";
import { nohupHandler } from "./command-nohup.js";
import { setsidHandler } from "./command-setsid.js";
import { stdbufHandler } from "./command-stdbuf.js";
import { straceHandler } from "./command-strace.js";
import { sudoeditHandler, sudoHandler } from "./command-sudo.js";
import { timeoutHandler } from "./command-timeout.js";
import { xargsHandler } from "./command-xargs.js";

/** Transparent command wrappers. Each handler owns only its documented grammar. */
export const wrapperHandlers: readonly CommandHandler[] = Object.freeze([
  envHandler,
  commandHandler,
  doasHandler,
  execHandler,
  niceHandler,
  nohupHandler,
  setsidHandler,
  stdbufHandler,
  timeoutHandler,
  straceHandler,
  sudoHandler,
  sudoeditHandler,
  xargsHandler,
  findHandler,
]);
