import { ghPrCreateRepositoryValues, hasUnknownNestedGhCommand, isGhPrCreateCommand, isKnownGhTopLevel } from "../../src/bash/handlers/gh-command-line.js";
import { findSubcommand } from "../../src/bash/handlers/gh-utils.js";
import { analyzeGhPrCreateInvocation, type GhPrCreatePolicy } from "../../src/bash/policies/gh-pr-create.js";
import { GH_GLOBAL_DEFER_ENVIRONMENT_NAMES } from "../../src/bash/policy-environment.js";
import { allow, deny, executableIs, hasInheritedExecutableFunction, hasKnownEnvironment, hasUnsafeEnvironment, ignore, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const gh = new Set(["gh"]);

export function createGhPrCreatePolicy(configuration: Pick<GhPrCreatePolicy, "allowedRepositories" | "allowedOrganizations">): CodePermissionDefinition {
  const policy = Object.freeze({
    enabled: true,
    allowedRepositories: Object.freeze([...configuration.allowedRepositories]),
    allowedOrganizations: Object.freeze([...configuration.allowedOrganizations]),
  });
  return Object.freeze({
    apiVersion: 1,
    layer: "permission" as const,
    select: Object.freeze([{ kind: "invocation" }]),
    evaluate(event) {
      if (!executableIs(event, gh)) return ignore();
      const args = knownArguments(event);
      if (!args) return unknownGhRoute(event);
      const subcommand = findSubcommand(args);
      if (!subcommand) return ignore();
      if (!isKnownGhTopLevel(subcommand.name)) return deny("Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead", event);
      if (hasUnknownNestedGhCommand(args)) return deny("Unknown nested gh command blocked: it could be a configured alias that bypasses the ghPrCreate policy; use a native gh command instead", event);
      if (subcommand.name === "api") return deny("GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead", event);
      if (subcommand.name === "alias" && ["set", "import"].includes(args[subcommand.index + 1] ?? "")) return deny("GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead", event);
      if (["extension", "ext", "extensions"].includes(subcommand.name) && args[subcommand.index + 1] === "exec") return deny("GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead", event);
      if (subcommand.name !== "pr" || !isGhPrCreateCommand(args)) return ignore();
      if (event.executable.value.includes("/") || Object.keys(event.assignments).some((name) => name !== "GH_PROMPT_DISABLED") || event.redirects.length > 0) {
        return deny("Pull-request creation is blocked through an explicit executable path, leading environment assignment, or redirection; invoke native gh pr create directly instead", event);
      }
      if (!hasKnownEnvironment(event, "GH_PROMPT_DISABLED")) return deny("Pull-request creation is blocked unless GH_PROMPT_DISABLED is explicitly present, preventing prompts and configured editor execution", event);
      if (hasUnsafeEnvironment(event, GH_GLOBAL_DEFER_ENVIRONMENT_NAMES)) return deny("GitHub CLI execution is blocked because an inherited or shell-assigned environment variable can redirect authentication, configuration, output, or external execution", event);
      if (hasInheritedExecutableFunction(event, "gh")) return deny("Pull-request creation is blocked because an inherited Bash function can replace the gh executable", event);
      if (event.provenance.route.some((route) => route === "eval" || route === "shell-command" || route === "binding-derived-script")) return deny("Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead", event);
      const decision = analyzeGhPrCreateInvocation(ghPrCreateRepositoryValues(args), policy);
      return decision.kind === "allow" ? allow(decision.reason, event) : deny(decision.reason, event);
    },
  });
}

export default createGhPrCreatePolicy({ allowedRepositories: [], allowedOrganizations: [] });

function unknownGhRoute(event: Extract<import("../../src/policy/types.js").BashPolicyEvent, { readonly kind: "invocation" }>) {
  const api = event.argv.some((argument) => argument.kind === "known" && argument.value === "api");
  const prIndex = event.argv.findIndex((argument) => argument.kind === "known" && argument.value === "pr");
  const prChild = prIndex >= 0 ? event.argv[prIndex + 1] : undefined;
  if (api) return deny("GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead", event);
  if (prIndex >= 0 && (!prChild || prChild.kind !== "known" || ["create", "new"].includes(prChild.value))) return deny("Pull-request creation is blocked when its command path or arguments cannot be resolved statically", event);
  return ignore();
}
