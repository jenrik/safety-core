import { analyzeGitReadOnlyInvocation } from "../../src/bash/policies/git.js";
import { readOnlyAllow } from "../../src/bash/policies/read-only-decision.js";
import { allow, defer, executableIs, hasExplicitExecutionRoute, hasInheritedExecutableFunction, hasUnsafeEnvironment, ignore, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const executables = new Set(["git", "sha256sum", "tea"]);
const gitEnvironment = ["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "PAGER"];

const policy: CodePermissionDefinition = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    if (!executableIs(event, executables)) return ignore();
    const args = knownArguments(event);
    if (!args || hasExplicitExecutionRoute(event) || hasInheritedExecutableFunction(event, event.executable.value)
      || (event.executable.value === "git" && hasUnsafeEnvironment(event, gitEnvironment))) return defer();
    if (event.executable.value === "sha256sum") return allow(readOnlyAllow("generic-read-only", "sha256sum").reason, event);
    if (event.executable.value === "tea") return args.length === 1 && args[0] === "--help"
      ? allow(readOnlyAllow("generic-read-only", "tea").reason, event)
      : defer();
    const decision = analyzeGitReadOnlyInvocation(args);
    return decision.kind === "allow" ? allow(decision.reason, event) : defer();
  },
});

export default policy;
