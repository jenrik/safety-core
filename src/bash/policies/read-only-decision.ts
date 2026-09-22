import type { PolicyEvidence } from "../outcome.js";

export type ReadOnlyPolicyName = "generic-read-only" | "gh-read-only" | "helm-read-only" | "strict-read-only";
export type ReadOnlyInvocationDecision =
  | { readonly kind: "allow"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "defer"; readonly evidence: PolicyEvidence };

export function readOnlyAllow(name: ReadOnlyPolicyName, tool: string): ReadOnlyInvocationDecision {
  const reason = `${tool} auto-allowed by the read-only profile`;
  return Object.freeze({ kind: "allow", reason, evidence: Object.freeze({ name, decision: "allow", reason, readOnly: Object.freeze({ tool }) }) });
}

export function readOnlyDefer(name: ReadOnlyPolicyName, tool: string): ReadOnlyInvocationDecision {
  return Object.freeze({ kind: "defer", evidence: Object.freeze({ name, decision: "defer", readOnly: Object.freeze({ tool }) }) });
}
