import { observePolicy, type PolicyObserver } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeSecretReadInvocation } from "../policies/secrets.js";

export function secretReaderHandler(name: string): PolicyObserver {
  return Object.freeze({
    name,
    observe(cursor, context) {
      const decision = analyzeSecretReadInvocation(cursor.invocation);
      return observePolicy(decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence));
    },
  });
}
