import { parseOptionChild, wrapperHandler } from "./wrapper-utils.js";

export const nohupHandler = wrapperHandler("nohup", (arguments_, context) =>
  parseOptionChild(arguments_, context, new Map(), new Set(["--"])),
);
