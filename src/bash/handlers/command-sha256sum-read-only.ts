import type { PolicyObserver } from "../dispatch.js";
import { allow, readOnlyHandler } from "./read-only-utils.js";

export const sha256sumReadOnlyHandler: PolicyObserver = readOnlyHandler("sha256sum", "generic-read-only", () =>
  allow("generic-read-only", "sha256sum"),
);
