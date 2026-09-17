import type { PolicyEvidence } from "../outcome.js";

export type GhApiInvocationDecision =
  | { readonly kind: "allow"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "deny"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "defer"; readonly evidence: PolicyEvidence };

export function analyzeGhApiInvocation(input: {
  readonly endpoint: string | undefined;
  readonly explicitMethod: string | undefined;
  readonly hasParametersOrBody: boolean;
  readonly methodAmbiguous?: boolean;
  readonly unsafeOrMalformed?: boolean;
}): GhApiInvocationDecision {
  if (input.methodAmbiguous) return defer();
  if (input.explicitMethod !== undefined) {
    const method = input.explicitMethod.toUpperCase();
    if (method !== "GET" && method !== "HEAD") return deny(`gh api --method ${method} is not read-only`);
  }
  if (!input.endpoint) return defer();
  if (input.explicitMethod === undefined && input.hasParametersOrBody) {
    return deny("gh api with -f/-F/--input and no explicit --method defaults to POST, not read-only");
  }
  if (/^\/?graphql(?:\/|\?|$)/.test(input.endpoint) || /^(?:https?:)?\/\//i.test(input.endpoint)) return defer();
  if (input.unsafeOrMalformed) return defer();
  if (input.explicitMethod !== undefined) return allow(`gh api --method ${input.explicitMethod.toUpperCase()} auto-allowed (read-only)`);
  return allow("gh api auto-allowed (GET, no parameters)");
}

function evidence(decision: PolicyEvidence["decision"], reason?: string): PolicyEvidence {
  return Object.freeze({ name: "gh-api", decision, ...(reason ? { reason } : {}) });
}

function allow(reason: string): GhApiInvocationDecision {
  return Object.freeze({ kind: "allow", reason, evidence: evidence("allow", reason) });
}

function deny(reason: string): GhApiInvocationDecision {
  return Object.freeze({ kind: "deny", reason, evidence: evidence("deny", reason) });
}

function defer(): GhApiInvocationDecision {
  return Object.freeze({ kind: "defer", evidence: evidence("defer") });
}
