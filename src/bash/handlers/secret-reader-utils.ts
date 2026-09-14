import type { CommandHandler } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeSecretReadInvocation } from "../policies/secrets.js";

export function secretReaderHandler(name: string): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor, context) {
      const decision = analyzeSecretReadInvocation(cursor.invocation);
      return decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence);
    },
  });
}
