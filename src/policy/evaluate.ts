import type {
  BashPolicyAnalysis,
  BashPolicyEvent,
  GuardBashPolicy,
  LoadedBashPolicy,
  PermissionBashPolicy,
  PolicyDecision,
  PolicyEvaluation,
  PolicyTrace,
  ValidatedBashPolicy,
} from "./types.js";

/**
 * Validate a loader-provided policy without assigning semantics to its source
 * path or selectors. Task 2 owns filesystem canonicalization; this boundary
 * rejects non-canonical path syntax and only accepts layer-correlated policies.
 */
export function validateLoadedBashPolicy(policy: GuardBashPolicy): GuardBashPolicy;
export function validateLoadedBashPolicy(policy: PermissionBashPolicy): PermissionBashPolicy;
export function validateLoadedBashPolicy(policy: ValidatedBashPolicy): ValidatedBashPolicy;
export function validateLoadedBashPolicy(policy: unknown): ValidatedBashPolicy {
  if (!policy || typeof policy !== "object") throw new TypeError("Bash policy must be an object");
  const candidate = policy as Partial<LoadedBashPolicy>;
  if (!candidate.source || !isCanonicalSourcePath(candidate.source.canonicalPath)) {
    throw new TypeError("Bash policy source must have a canonical absolute path");
  }
  if (candidate.layer !== "guard" && candidate.layer !== "permission") throw new TypeError("Bash policy layer must be guard or permission");
  if (!Array.isArray(candidate.select)) throw new TypeError("Bash policy selectors must be an array");
  if (typeof candidate.evaluate !== "function") throw new TypeError("Bash policy must evaluate events");
  return candidate as ValidatedBashPolicy;
}

/**
 * Combine independently evaluated policy decisions. A denial is dominant;
 * permission allows cover only their invocation, and all reachable work must
 * be complete and covered before the request can be allowed.
 */
export function evaluatePolicyEvents(
  events: readonly BashPolicyEvent[],
  policies: readonly ValidatedBashPolicy[],
  analysis: BashPolicyAnalysis,
): PolicyEvaluation {
  const validatedPolicies = policies.map((policy) => validateLoadedBashPolicy(policy));
  const traces: PolicyTrace[] = [];
  const coveredInvocations = new Set<number>();
  let denied = false;
  let hasExecutionGap = false;

  for (const [eventIndex, event] of events.entries()) {
    if (event.kind === "execution-gap") hasExecutionGap = true;
    for (const policy of validatedPolicies) {
      const decision = policy.evaluate(event);
      assertPolicyDecision(decision);
      if (policy.layer === "guard" && decision.kind === "allow") {
        throw new Error("Guard policies cannot allow; guards may only deny, defer, or ignore");
      }

      traces.push(Object.freeze({
        source: policy.source,
        layer: policy.layer,
        event,
        decision,
      }));

      if (decision.kind === "deny") denied = true;
      if (event.kind === "invocation" && policy.layer === "permission" && decision.kind === "allow"
        && (event.missingBindings === "unset" || policy.select.some((selector) => selector.environmentIndependent === true))) {
        coveredInvocations.add(eventIndex);
      }
    }
  }

  const allInvocationsCovered = events.every((event, index) =>
    event.kind !== "invocation" || coveredInvocations.has(index)
  );
  const decision = denied
    ? "deny"
    : analysis.complete && !hasExecutionGap && allInvocationsCovered
      ? "allow"
      : "defer";

  return Object.freeze({ decision, traces: Object.freeze(traces) });
}

function assertPolicyDecision(decision: PolicyDecision): void {
  if (!decision || typeof decision !== "object") throw new TypeError("Policy evaluation must return a decision");
  if (decision.kind === "allow" || decision.kind === "deny") {
    if (!Array.isArray(decision.reason)) throw new TypeError(`${decision.kind} decisions require a reason template`);
    return;
  }
  if (decision.kind === "defer") {
    if (decision.reason !== undefined && !Array.isArray(decision.reason)) throw new TypeError("Defer reason must be a template");
    return;
  }
  if (decision.kind !== "ignore") throw new TypeError("Unknown policy decision kind");
}

/** Checks portable canonical-path syntax without resolving the filesystem. */
function isCanonicalSourcePath(path: string): boolean {
  return path === "/" || (path.startsWith("/") && path.split("/").slice(1).every((part) => part !== "" && part !== "." && part !== ".."));
}
