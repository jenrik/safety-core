import type { PolicyObserver } from "../dispatch.js";
import { analyzeGitReadOnlyInvocation } from "../policies/git.js";
import { readOnlyHandler } from "./read-only-utils.js";

export const gitReadOnlyHandler: PolicyObserver = readOnlyHandler("git", "generic-read-only", analyzeGitReadOnlyInvocation);
