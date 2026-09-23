import { kubectlResourceOperandsRequireReview } from "../../../src/bash/policies/kubectl.js";
import { readOnlyAllow } from "../../../src/bash/policies/read-only-decision.js";
import { STRICT_ALLOWED_FLAGS, STRICT_READ_ONLY_COMMANDS } from "../../../src/bash/policies/read-only-data.js";
import { allow, defer, executableIs, hasExplicitExecutionRoute, hasInheritedExecutableFunction, hasUnsafeEnvironment, ignore, isSecretPath, knownArguments, type CodePermissionDefinition } from "./permission-utils.js";

const executables = new Set(Object.keys(STRICT_READ_ONLY_COMMANDS));

const policy: CodePermissionDefinition = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    if (!executableIs(event, executables)) return ignore();
    const executable = event.executable.value;
    const args = knownArguments(event);
    const unsafeEnvironment = executable === "docker" ? ["DOCKER_CONFIG"] : ["kubectl", "oc"].includes(executable) ? ["KUBECONFIG"] : [];
    if (!args || hasExplicitExecutionRoute(event) || hasInheritedExecutableFunction(event, executable)
      || hasUnsafeEnvironment(event, unsafeEnvironment) || args.some((argument) => !argument.startsWith("-") && isSecretPath(argument))) return defer();
    if (args.length === 1 && ["--help", "--version", "version"].includes(args[0]!)) return allow(readOnlyAllow("strict-read-only", executable).reason, event);
    const positionals = parseAllowedFlags(args, STRICT_ALLOWED_FLAGS[executable] ?? []);
    const path = positionals && strictPath(positionals, STRICT_READ_ONLY_COMMANDS[executable]!);
    if (!path || path === "version" && positionals!.length !== 1) return defer();
    if (["kubectl", "oc"].includes(executable) && path === "get") {
      const resources = positionals!.slice(1);
      if (resources.length === 0 || kubectlResourceOperandsRequireReview(resources)) return defer();
    }
    return allow(readOnlyAllow("strict-read-only", executable).reason, event);
  },
});

export default policy;

function parseAllowedFlags(args: readonly string[], specs: readonly { readonly long?: string; readonly short?: string; readonly takesValue: boolean }[]): string[] | undefined {
  const positionals: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") return undefined;
    if (!argument.startsWith("-") || argument === "-") { positionals.push(argument); continue; }
    const exact = specs.find((spec) => argument === spec.long || argument === spec.short);
    if (exact) {
      if (!exact.takesValue) continue;
      const value = args[++index];
      if (!value || value.startsWith("-")) return undefined;
      continue;
    }
    const long = specs.find((spec) => spec.takesValue && spec.long && argument.startsWith(`${spec.long}=`));
    if (long) { if (!argument.slice(argument.indexOf("=") + 1)) return undefined; continue; }
    const short = specs.find((spec) => spec.takesValue && spec.short && argument.startsWith(spec.short) && argument.length > spec.short.length);
    if (short) { if (!argument.slice(short.short!.length).replace(/^=/, "")) return undefined; continue; }
    return undefined;
  }
  return positionals;
}

function strictPath(args: readonly string[], allowed: ReadonlySet<string>): string | undefined {
  return [...allowed].sort((left, right) => right.split(":").length - left.split(":").length)
    .find((path) => path.split(":").every((token, index) => args[index] === token));
}
