import type { StructuralHandler } from "../dispatch.js";
import { shellHandlers } from "./sh.js";
import { wrapperHandlers } from "./wrappers.js";
import { unknownCommandHandler } from "./unknown.js";

/** Structural handlers always run; profile policies are registered by their caller. */
export const structuralHandlers: readonly StructuralHandler[] = Object.freeze([
  ...wrapperHandlers,
  ...shellHandlers,
]);

export const unknownStructuralHandler = unknownCommandHandler;
