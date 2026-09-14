import type { CommandHandler } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeGithubHttpInvocation } from "../policies/github.js";

export function githubHttpHandler(name: string): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor, context) {
      const decision = analyzeGithubHttpInvocation(cursor.invocation);
      return decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence);
    },
  });
}
