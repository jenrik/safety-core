import { ignorePolicy, observePolicy, type PolicyObserver } from "../dispatch.js";
import { policyDeny, policyIndeterminate, policySafe } from "../outcome.js";
import { analyzeKubectlInvocation } from "../policies/kubectl.js";

export const kubectlHandler = Object.freeze<PolicyObserver>({
  name: "kubectl",
  observe(cursor, context) {
    const decision = analyzeKubectlInvocation(cursor.invocation);
    switch (decision.kind) {
      case "allow":
        return observePolicy(policySafe(decision.evidence));
      case "deny":
        return observePolicy(policyDeny(context.span, decision.evidence));
      case "defer":
        return observePolicy(policyIndeterminate(context.span, decision.evidence));
      case "ignore":
        return ignorePolicy();
    }
  },
});
