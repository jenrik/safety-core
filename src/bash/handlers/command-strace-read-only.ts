import type { PolicyObserver } from "../dispatch.js";
import { readOnlyStraceObservation } from "./read-only-utils.js";

/** strace is transparent unless its trace-output options would create a file. */
export const straceReadOnlyHandler: PolicyObserver = Object.freeze({
  name: "strace",
  observe(cursor, context) {
    return readOnlyStraceObservation(cursor, context.span);
  },
});
