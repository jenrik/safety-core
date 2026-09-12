import type { CommandHandler } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeSecretReadInvocation } from "../policies/secrets.js";
import { READING_COMMANDS } from "../../patterns.js";

export const readerHandlers: readonly CommandHandler[] = Object.freeze(
  [...READING_COMMANDS].map((name) => Object.freeze({
    name,
    handle(cursor, context) {
      const decision = analyzeSecretReadInvocation(cursor.invocation);
      return decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence);
    },
  })),
);
