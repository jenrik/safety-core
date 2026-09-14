import { parseOptionChild, wrapperHandler } from "./wrapper-utils.js";

export const niceHandler = wrapperHandler("nice", (arguments_, context) =>
  parseOptionChild(arguments_, context, new Map([["-n", 1], ["--adjustment", 1]]), new Set(["--"]), ["-n", "--adjustment="]),
);
