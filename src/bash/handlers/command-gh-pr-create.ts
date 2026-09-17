import { ignorePolicy, observePolicy, type PolicyDispatchContext, type PolicyObserver } from "../dispatch.js";
import { policyDeny, policyIndeterminate } from "../outcome.js";
import { analyzeGhPrCreateInvocation, denyGhPrCreate, type GhPrCreatePolicy } from "../policies/gh-pr-create.js";
import { GH_GLOBAL_DEFER_ENVIRONMENT_NAMES } from "../policy-environment.js";
import { ghPrCreateRepositoryValues, hasUnknownNestedGhCommand, isGhPrCreateCommand, isKnownGhTopLevel } from "./gh-command-line.js";
import { commandScript, findSubcommand, knownArguments } from "./gh-utils.js";
import { hasDisabledGhPrompts, hasInheritedExecutableFunction, hasUnsafeGhEnvironmentBinding } from "./read-only-utils.js";

export function ghPrCreateHandler(policy: GhPrCreatePolicy): PolicyObserver {
  return Object.freeze({
    name: "gh",
    observe(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) {
        const first = cursor.invocation.argv[0];
        const api = cursor.invocation.argv.some((argument) => argument.kind === "known" && argument.value === "api");
        const prIndex = cursor.invocation.argv.findIndex((argument) => argument.kind === "known" && argument.value === "pr");
        const prChild = prIndex >= 0 ? cursor.invocation.argv[prIndex + 1] : undefined;
        if (api) return denied(context, "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead");
        if (prIndex >= 0 && (!prChild || prChild.kind !== "known" || ["create", "new"].includes(prChild.value))) {
          return denied(context, "Pull-request creation is blocked when its command path or arguments cannot be resolved statically");
        }
        const conservativeArgs = cursor.invocation.argv.map((argument) => argument.kind === "known" ? argument.value : "safety-core-unresolved-command");
        if (isGhPrCreateCommand(conservativeArgs)) {
          return denied(context, "Pull-request creation is blocked when its command path or arguments cannot be resolved statically");
        }
        if (hasUnknownNestedGhCommand(conservativeArgs)) {
          return denied(context, "Unknown nested gh command blocked: it could be a configured alias that bypasses the ghPrCreate policy; use a native gh command instead");
        }
        return first?.kind !== "known" || !isKnownGhTopLevel(first.value)
          ? denied(context, "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead")
          : ["alias", "extension", "ext", "extensions"].includes(first.value)
            ? denied(context, first.value === "alias"
            ? "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead"
            : "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead")
            : ignorePolicy();
      }
      const subcommand = findSubcommand(args);
      if (!subcommand) return ignorePolicy();
      if (!isKnownGhTopLevel(subcommand.name)) return denied(context, "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead");
      if (hasUnknownNestedGhCommand(args)) return denied(context, "Unknown nested gh command blocked: it could be a configured alias that bypasses the ghPrCreate policy; use a native gh command instead");
      if (subcommand.name === "api") return denied(context, "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead");
      if (subcommand.name === "alias" && ["set", "import"].includes(args[subcommand.index + 1] ?? "")) {
        return denied(context, "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead");
      }
      if (["extension", "ext", "extensions"].includes(subcommand.name) && args[subcommand.index + 1] === "exec") {
        return denied(context, "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead");
      }
      if (subcommand.name !== "pr" || !isGhPrCreateCommand(args)) return ignorePolicy();
      const executable = cursor.invocation.executable;
      const assignmentWrites = cursor.invocation.assignmentPatch.writes;
      if ((executable?.kind === "known" && executable.value.includes("/"))
        || [...assignmentWrites].some((name) => name !== "GH_PROMPT_DISABLED")
        || cursor.invocation.redirects.length > 0) {
        return denied(context, "Pull-request creation is blocked through an explicit executable path, leading environment assignment, or redirection; invoke native gh pr create directly instead");
      }
      if (!hasDisabledGhPrompts(cursor)) {
        return denied(context, "Pull-request creation is blocked unless GH_PROMPT_DISABLED is explicitly present, preventing prompts and configured editor execution");
      }
      if (hasUnsafeGhEnvironmentBinding(cursor, GH_GLOBAL_DEFER_ENVIRONMENT_NAMES)) {
        return denied(context, "GitHub CLI execution is blocked because an inherited or shell-assigned environment variable can redirect authentication, configuration, output, or external execution");
      }
      if (hasInheritedExecutableFunction(cursor, "gh")) {
        return denied(context, "Pull-request creation is blocked because an inherited Bash function can replace the gh executable");
      }
      if (context.provenance.route.some((route) => route === "eval" || route === "shell-command" || route === "binding-derived-script")) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      const decision = analyzeGhPrCreateInvocation(ghPrCreateRepositoryValues(args), policy);
      return observePolicy(decision.kind === "allow"
        ? policyIndeterminate(context.span, Object.freeze({
          ...decision.evidence,
          decision: "defer" as const,
          reason: "Allowlisted pull-request creation remains prompt-gated because GitHub CLI startup state is mutable",
        }))
        : policyDeny(context.span, decision.evidence));
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
