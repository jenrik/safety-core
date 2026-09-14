import { parseOptionChild, wrapperHandler } from "./wrapper-utils.js";

export const stdbufHandler = wrapperHandler("stdbuf", (arguments_, context) =>
  parseOptionChild(
    arguments_,
    context,
    new Map([["-i", 1], ["-o", 1], ["-e", 1]]),
    new Set(["--"]),
    ["--input=", "--output=", "--error=", "-i", "-o", "-e"],
  ),
);
