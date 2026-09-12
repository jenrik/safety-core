import type { CommandHandler } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeGithubHttpInvocation } from "../policies/github.js";
import { HTTP_TOOLS } from "../../patterns.js";

export const httpHandlers: readonly CommandHandler[] = Object.freeze(
  [...HTTP_TOOLS].map((name) => Object.freeze({
    name,
    handle(cursor, context) {
      const decision = analyzeGithubHttpInvocation(cursor.invocation);
      return decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policySafe(decision.evidence);
    },
  })),
);
