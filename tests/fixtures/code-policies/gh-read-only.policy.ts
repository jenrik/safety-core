import { ghCommandGrammarMatches, parseGhCommandLine } from "../../../src/bash/handlers/gh-command-line.js";
import { readOnlyAllow } from "../../../src/bash/policies/read-only-decision.js";
import { GH_DEFER_ENVIRONMENT_NAMES } from "../../../src/bash/policy-environment.js";
import { allow, defer, executableIs, hasExplicitExecutionRoute, hasInheritedExecutableFunction, hasUnsafeEnvironment, ignore, isSecretPath, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const gh = new Set(["gh"]);

const policy: CodePermissionDefinition = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    if (!executableIs(event, gh)) return ignore();
    const args = knownArguments(event);
    if (!args || hasExplicitExecutionRoute(event) || hasInheritedExecutableFunction(event, "gh") || hasUnsafeEnvironment(event, GH_DEFER_ENVIRONMENT_NAMES)) return defer();
    if (args.some((argument) => !argument.startsWith("-") && isSecretPath(argument))) return defer();
    const parsed = parseGhCommandLine(args);
    if (parsed.kind === "command" && parsed.rule.path.join(" ") === "api") return ignore();
    if (parsed.kind === "command" && parsed.rule.disposition === "allow" && ghCommandGrammarMatches(parsed)) {
      return allow(readOnlyAllow("gh-read-only", "gh").reason, event);
    }
    return defer();
  },
});

export default policy;
