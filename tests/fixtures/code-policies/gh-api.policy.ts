import { parseGhApiArguments } from "../../../src/bash/policies/gh-api-parser.js";
import { findSubcommand } from "../../../src/bash/handlers/gh-utils.js";
import { analyzeGhApiInvocation } from "../../../src/bash/policies/gh-api.js";
import { GH_API_DEFER_ENVIRONMENT_NAMES } from "../../../src/bash/policy-environment.js";
import { allow, defer, deny, executableIs, hasExplicitExecutionRoute, hasInheritedExecutableFunction, hasKnownExportedEnvironment, hasUnsafeEnvironment, ignore, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const gh = new Set(["gh"]);

const policy: CodePermissionDefinition = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    if (!executableIs(event, gh)) return ignore();
    const args = knownArguments(event);
    if (!args) return event.argv.some((argument) => argument.kind === "known" && argument.value === "api") ? defer() : ignore();
    const subcommand = findSubcommand(args);
    if (!subcommand || subcommand.name !== "api") return ignore();
    const parsed = parseGhApiArguments(args, subcommand.index);
    const disabledPager = hasKnownExportedEnvironment(event, "GH_PAGER") && ["", "cat"].includes(event.environment.GH_PAGER!.value);
    const decision = analyzeGhApiInvocation({
      endpoint: parsed.endpoint,
      explicitMethod: parsed.explicitMethod,
      hasParametersOrBody: parsed.hasParametersOrBody,
      methodAmbiguous: parsed.methodAmbiguous,
      unsafeOrMalformed: parsed.unsafeOrMalformed
        || hasExplicitExecutionRoute(event, ["GH_PAGER"])
        || hasInheritedExecutableFunction(event, "gh")
        || !disabledPager
        || hasUnsafeEnvironment(event, GH_API_DEFER_ENVIRONMENT_NAMES),
    });
    return decision.kind === "allow" ? allow(decision.reason, event) : decision.kind === "deny" ? deny(decision.reason, event) : defer();
  },
});

export default policy;
