import { observePolicy, type PolicyObserver } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeGithubHttpInvocation } from "../policies/github.js";

export function githubHttpHandler(name: string): PolicyObserver {
  return Object.freeze({
    name,
    observe(cursor, context) {
      const decision = analyzeGithubHttpInvocation(cursor.invocation);
      return observePolicy(decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence));
    },
  });
}
