// Credential-safe CLI compatibility adapters backed by the stateful Bash walker.

import { analyzeBashAuthorization, type BashAuthorizationContext } from "./authorization.js";
import { ghReadOnlyHandlers, helmReadOnlyHandlers, strictReadOnlyHandlers } from "./bash/handlers/read-only.js";
import type { CommandHandler } from "./bash/dispatch.js";

export type ReadOnlyCliDecision =
  | { kind: "allow"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

export function analyzeStrictReadOnlyCommand(command: string, executable: string, context: BashAuthorizationContext = {}): ReadOnlyCliDecision {
  return analyze(command, "strict-read-only", executable, strictReadOnlyHandlers(executable), context);
}

export function analyzeGhReadOnlyCommand(command: string, context: BashAuthorizationContext = {}): ReadOnlyCliDecision {
  return analyze(command, "gh-read-only", "gh", ghReadOnlyHandlers, context);
}

export function analyzeHelmReadOnlyCommand(command: string, context: BashAuthorizationContext = {}): ReadOnlyCliDecision {
  return analyze(command, "helm-read-only", "helm", helmReadOnlyHandlers, context);
}

function analyze(command: string, name: "strict-read-only" | "gh-read-only" | "helm-read-only", executable: string, handlers: readonly CommandHandler[], context: BashAuthorizationContext): ReadOnlyCliDecision {
  const analysis = analyzeBashAuthorization({ source: command, handlers, includeBaseHandlers: false, ...context });
  const policies = analysis.policies.filter((evidence) => evidence.name === name && evidence.readOnly?.tool === executable);
  const policy = policies[0];
  if (!policy) return { kind: "ignore" };
  if (policy.decision === "allow" && policies.every((evidence) => evidence.decision === "allow") && analysis.verdict.kind === "allow") {
    return { kind: "allow", reason: policy.reason ?? `${executable} auto-allowed by the read-only profile` };
  }
  return { kind: "defer" };
}
