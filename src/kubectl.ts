// kubectl-specific policy compatibility adapters backed by the Bash walker.

import { analyzeBashAuthorization, type BashAuthorizationContext } from "./authorization.js";
import {
  isProtectedKubectlResource,
  kubectlResourceOperandsRequireReview,
  kubectlResourceType,
} from "./bash/policies/kubectl.js";

export type KubectlDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

/** Analyze the first walker-observed kubectl policy decision for compatibility. */
export function analyzeKubectl(command: string, context: BashAuthorizationContext = {}): KubectlDecision {
  const policy = analyzeBashAuthorization({ source: command, ...context }).policies
    .find((evidence) => evidence.name === "kubectl");
  if (policy?.name !== "kubectl") return { kind: "ignore" };
  switch (policy.decision) {
    case "allow": return { kind: "allow", reason: policy.reason ?? "kubectl auto-allowed" };
    case "deny": return { kind: "deny", reason: policy.reason ?? "kubectl command is blocked" };
    case "defer": return { kind: "defer" };
  }
}

/** Hard-block adapter for kubectl operations that can expose Secret values. */
export function checkBashForKubectlSecret(command: string, context: BashAuthorizationContext = {}): string | null {
  const policy = analyzeBashAuthorization({ source: command, ...context }).policies
    .find((evidence) => evidence.name === "kubectl" && (evidence.decision === "deny" || evidence.kubectl?.secretReview));
  if (!policy) return null;
  if (policy.decision === "deny") return policy.reason ?? null;
  if (policy.decision === "defer" && policy.kubectl?.secretReview) {
    return "kubectl get Secret is not auto-approved. Use metadata-only output or request confirmation for a safe command.";
  }
  return null;
}

export interface KubectlAuditRecord {
  kubectl_subcommand: string | null;
  resource: string | null;
  command_length: number;
}

/** Return a redacted audit summary for a kubectl command that mentions Secrets. */
export function summariseKubectlSecret(command: string, context: BashAuthorizationContext = {}): KubectlAuditRecord | null {
  const policy = analyzeBashAuthorization({ source: command, ...context }).policies
    .find((evidence) => evidence.name === "kubectl" && evidence.kubectl?.mentionsSecret);
  if (!policy?.kubectl) return null;
  return {
    kubectl_subcommand: policy.kubectl.subcommand,
    resource: policy.kubectl.resource,
    command_length: command.length,
  };
}

export { isProtectedKubectlResource, kubectlResourceOperandsRequireReview, kubectlResourceType };
