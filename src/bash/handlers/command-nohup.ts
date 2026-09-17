import { parseOptionChild, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

export const nohupHandler = wrapperHandler("nohup", (arguments_, context) =>
  taintWrapperResult(parseOptionChild(arguments_, context, new Map(), new Set(["--"])), context),
);
