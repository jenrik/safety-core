import { readOnlyAllow } from "../../../src/bash/policies/read-only-decision.js";
import { HELM_CREDENTIAL_SAFE_COMMANDS } from "../../../src/bash/policies/read-only-data.js";
import { allow, defer, executableIs, hasExplicitExecutionRoute, hasInheritedExecutableFunction, ignore, isSecretPath, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const helm = new Set(["helm"]);

const policy: CodePermissionDefinition = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    if (!executableIs(event, helm)) return ignore();
    const args = knownArguments(event);
    if (!args || hasExplicitExecutionRoute(event) || hasInheritedExecutableFunction(event, "helm") || args.some((argument) => !argument.startsWith("-") && isSecretPath(argument))) return defer();
    const allowed = args.length === 1 && ["--help", "--version"].includes(args[0]!)
      || args[0] === "help"
      || args[0] === "completion" && args.length === 2
      || args[0] === "verify" && args.length >= 2
      || ["show:chart", "inspect:chart"].includes(args.slice(0, 2).join(":")) && args.length === 3
      || HELM_CREDENTIAL_SAFE_COMMANDS.has(args.slice(0, 2).join(":"));
    return !args[0] || args.some((argument) => argument.startsWith("-")) && !(args.length === 1 && ["--help", "--version"].includes(args[0]!))
      ? defer()
      : allowed ? allow(readOnlyAllow("helm-read-only", "helm").reason, event) : defer();
  },
});

export default policy;
