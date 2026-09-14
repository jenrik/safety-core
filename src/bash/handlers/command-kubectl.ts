import type { CommandHandler } from "../dispatch.js";
import { indeterminate, policyDeny, policyIndeterminate, policySafe } from "../outcome.js";
import { analyzeKubectlInvocation } from "../policies/kubectl.js";

export const kubectlHandler: CommandHandler = Object.freeze({
  name: "kubectl",
  handle(cursor, context) {
    const decision = analyzeKubectlInvocation(cursor.invocation);
    switch (decision.kind) {
      case "allow": return policySafe(decision.evidence);
      case "deny": return policyDeny(context.span, decision.evidence);
      case "defer": return policyIndeterminate(context.span, decision.evidence);
      case "ignore": return indeterminate(context.span);
    }
  },
});
