// Credential-safe CLI compatibility adapters backed by the stateful Bash walker.
// TODO: Remove these profile-specific whole-command wrappers after the
// configured core evaluator selects every enabled read-only policy in one pass.

import { analyzeBashAuthorization, type BashAuthorizationContext } from "./authorization.js";
import { genericReadOnlyHandlers, ghReadOnlyHandlers, helmReadOnlyHandlers, strictReadOnlyHandlers } from "./bash/handlers/read-only.js";
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

/** Parsed additions to the static readOnlyBash profile. */
export function analyzeGenericReadOnlyCommand(command: string, context: BashAuthorizationContext = {}): ReadOnlyCliDecision {
  const analysis = analyzeBashAuthorization({ source: command, handlers: genericReadOnlyHandlers, includeBaseHandlers: false, ...context });
  const policies = analysis.policies.filter((evidence) => evidence.name === "generic-read-only");
  const policy = policies[0];
  if (!policy) return { kind: "ignore" };
  if (policies.every((evidence) => evidence.decision === "allow") && analysis.verdict.kind === "allow") {
    return { kind: "allow", reason: policy.reason ?? "command auto-allowed by the read-only profile" };
  }
  return { kind: "defer" };
}

function analyze(command: string, name: "strict-read-only" | "gh-read-only" | "helm-read-only", executable: string, handlers: readonly CommandHandler[], context: BashAuthorizationContext): ReadOnlyCliDecision {
  const analysis = analyzeBashAuthorization({ source: command, handlers, includeBaseHandlers: false, ...context });
  if (analysis.policies.some((evidence) => evidence.name === "generic-read-only" && evidence.decision === "defer")) {
    return { kind: "defer" };
  }
  const policies = analysis.policies.filter((evidence) => evidence.name === name && evidence.readOnly?.tool === executable);
  const policy = policies[0];
  if (!policy) return { kind: "ignore" };
  if (policy.decision === "allow" && policies.every((evidence) => evidence.decision === "allow") && analysis.verdict.kind === "allow") {
    return { kind: "allow", reason: policy.reason ?? `${executable} auto-allowed by the read-only profile` };
  }
  return { kind: "defer" };
}
