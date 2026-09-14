import type { GhPrCreatePolicy } from "../../gh-pr-create.js";
import type { CommandHandler } from "../dispatch.js";
import { indeterminate, policyDeny, policySafe } from "../outcome.js";
import { analyzeGhPrCreateInvocation, denyGhPrCreate } from "../policies/gh-pr-create.js";
import { KNOWN_TOP_LEVEL, findSubcommand, isPrCreate, knownArguments, repositoryValues } from "./gh-utils.js";

export function ghPrCreateHandler(policy: GhPrCreatePolicy): CommandHandler {
  return Object.freeze({
    name: "gh",
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) {
        const first = cursor.invocation.argv[0];
        return first?.kind === "known" && ["alias", "extension", "ext", "extensions"].includes(first.value)
          ? denied(context, first.value === "alias"
            ? "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead"
            : "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead")
          : indeterminate(context.span);
      }
      const subcommand = findSubcommand(args);
      if (!subcommand) return indeterminate(context.span);
      if (!KNOWN_TOP_LEVEL.has(subcommand.name)) return denied(context, "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead");
      if (subcommand.name === "api") return denied(context, "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead");
      if (subcommand.name === "alias" && ["set", "import"].includes(args[subcommand.index + 1] ?? "")) {
        return denied(context, "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead");
      }
      if (["extension", "ext", "extensions"].includes(subcommand.name) && args[subcommand.index + 1] === "exec") {
        return denied(context, "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead");
      }
      if (subcommand.name !== "pr" || !isPrCreate(args.slice(subcommand.index + 1))) return indeterminate(context.span);
      const decision = analyzeGhPrCreateInvocation(repositoryValues(args), policy);
      return decision.kind === "allow" ? policySafe(decision.evidence) : policyDeny(context.span, decision.evidence);
    },
  });
}

function denied(context: Parameters<CommandHandler["handle"]>[1], reason: string) {
  return policyDeny(context.span, denyGhPrCreate(reason).evidence);
}
