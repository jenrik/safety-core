import { parseOptionChild, wrapperHandler } from "./wrapper-utils.js";

export const setsidHandler = wrapperHandler("setsid", (arguments_, context) =>
  parseOptionChild(arguments_, context, new Map(), new Set(["-c", "--ctty", "-f", "--fork", "-w", "--wait", "--"])),
);
