import { ignorePolicy, observePolicy, type PolicyDispatchContext, type PolicyObserver } from "../dispatch.js";
import { policyDeny, policySafe } from "../outcome.js";
import { analyzeGhPrCreateInvocation, denyGhPrCreate, type GhPrCreatePolicy } from "../policies/gh-pr-create.js";
import { KNOWN_TOP_LEVEL, commandScript, findSubcommand, isPrCreate, knownArguments, repositoryValues } from "./gh-utils.js";

export function ghPrCreateHandler(policy: GhPrCreatePolicy): PolicyObserver {
  return Object.freeze({
    name: "gh",
    observe(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) {
        const first = cursor.invocation.argv[0];
        return first?.kind === "known" && ["alias", "extension", "ext", "extensions"].includes(first.value)
          ? denied(context, first.value === "alias"
            ? "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead"
            : "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead")
          : ignorePolicy();
      }
      const subcommand = findSubcommand(args);
      if (!subcommand) return ignorePolicy();
      if (!KNOWN_TOP_LEVEL.has(subcommand.name)) return denied(context, "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead");
      if (subcommand.name === "api") return denied(context, "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead");
      if (subcommand.name === "alias" && ["set", "import"].includes(args[subcommand.index + 1] ?? "")) {
        return denied(context, "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead");
      }
      if (["extension", "ext", "extensions"].includes(subcommand.name) && args[subcommand.index + 1] === "exec") {
        return denied(context, "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead");
      }
      if (subcommand.name !== "pr" || !isPrCreate(args.slice(subcommand.index + 1))) return ignorePolicy();
      if (context.provenance.route.some((route) => route === "eval" || route === "shell-command" || route === "binding-derived-script")) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      const decision = analyzeGhPrCreateInvocation(repositoryValues(args), policy);
      return observePolicy(decision.kind === "allow" ? policySafe(decision.evidence) : policyDeny(context.span, decision.evidence));
    },
  });
}

function denied(context: PolicyDispatchContext, reason: string) {
  return observePolicy(policyDeny(context.span, denyGhPrCreate(reason).evidence));
}

const SHELL_INTERPRETERS = ["eval", "sh", "bash", "dash", "fish", "ksh", "zsh"] as const;

/** Pipeline-fed interpreters consume unmodelled stdin and cannot safely execute a PR route. */
export const ghPrCreateInterpreterObservers: readonly PolicyObserver[] = Object.freeze(
  SHELL_INTERPRETERS.map((name) => Object.freeze({
    name,
    observe(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return ignorePolicy();
      const script = name === "eval" ? args.join(" ") : commandScript(args);
      return !script && context.inPipeline
        ? denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead")
        : ignorePolicy();
    },
  })),
);
