import type { CommandHandler } from "../dispatch.js";
import { shellHandlers } from "./sh.js";
import { wrapperHandlers } from "./wrappers.js";

/** Structural handlers always run; profile policies are registered by their caller. */
export const structuralHandlers: readonly CommandHandler[] = Object.freeze([
  ...wrapperHandlers,
  ...shellHandlers,
]);
