// Credential-safe CLI compatibility adapters backed by the stateful Bash walker.

import { analyzeBashAuthorization } from "./authorization.js";
import { ghReadOnlyHandlers, helmReadOnlyHandlers, strictReadOnlyHandlers } from "./bash/handlers/read-only.js";
import type { CommandHandler } from "./bash/dispatch.js";

export type ReadOnlyCliDecision =
  | { kind: "allow"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

export function analyzeStrictReadOnlyCommand(command: string, executable: string): ReadOnlyCliDecision {
  return analyze(command, "strict-read-only", executable, strictReadOnlyHandlers(executable));
}

export function analyzeGhReadOnlyCommand(command: string): ReadOnlyCliDecision {
  return analyze(command, "gh-read-only", "gh", ghReadOnlyHandlers);
}

export function analyzeHelmReadOnlyCommand(command: string): ReadOnlyCliDecision {
  return analyze(command, "helm-read-only", "helm", helmReadOnlyHandlers);
}

function analyze(command: string, name: "strict-read-only" | "gh-read-only" | "helm-read-only", executable: string, handlers: readonly CommandHandler[]): ReadOnlyCliDecision {
  const analysis = analyzeBashAuthorization({ source: command, handlers, includeBaseHandlers: false });
  const policies = analysis.policies.filter((evidence) => evidence.name === name && evidence.readOnly?.tool === executable);
  const policy = policies[0];
  if (!policy) return { kind: "ignore" };
  if (policy.decision === "allow" && policies.every((evidence) => evidence.decision === "allow") && analysis.verdict.kind === "allow") {
    return { kind: "allow", reason: policy.reason ?? `${executable} auto-allowed by the read-only profile` };
  }
  return { kind: "defer" };
}
