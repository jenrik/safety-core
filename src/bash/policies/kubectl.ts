import type { NormalizedCommand, ResolvedWord } from "../expand.js";
import {
  KUBECTL_ALWAYS_ALLOW,
  KUBECTL_AUTH_ALLOW,
  KUBECTL_FLAGS_WITH_VALUES,
  KUBECTL_PROTECTED_TYPES,
  KUBECTL_ROLLOUT_ALLOW,
} from "../../patterns.js";
import type { PolicyEvidence } from "../outcome.js";

export type KubectlInvocationDecision =
  | { readonly kind: "allow"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "deny"; readonly reason: string; readonly evidence: PolicyEvidence }
  | { readonly kind: "defer"; readonly evidence: PolicyEvidence }
  | { readonly kind: "ignore" };

export function analyzeKubectlInvocation(invocation: NormalizedCommand): KubectlInvocationDecision {
  const args = knownArguments(invocation.argv);
  if (!args) return defer(null, null, false);
  if (args.length === 0) return Object.freeze({ kind: "ignore" });
  const subcommandIndex = findSubcommandIndex(args);
  const sub = subcommandIndex === undefined ? null : args[subcommandIndex] ?? null;
  if (!sub) return defer(null, null, false);
  const mentionsSecret = args.some(mentionsSecretResource);
  const operands = positionalArgs(args, subcommandIndex + 1);
  const auditResource = operands[0] ? resourceType(operands[0]) : null;
  if (sub === "view-secret") return deny(
    "kubectl view-secret is blocked: it decodes and displays Secret values in plaintext.",
    sub,
    auditResource,
    mentionsSecret,
  );
  if (KUBECTL_ALWAYS_ALLOW.has(sub)) return allow(`kubectl ${sub} auto-allowed (read-only)`, sub, auditResource, mentionsSecret);
  if (sub === "get") {
    const resources = operands;
    if (resources.length === 0) return defer(sub, null, false);
    const requiresReview = kubectlResourceOperandsRequireReview(resources);
    const resource = resourceType(resources[0]!);
    return requiresReview ? defer(sub, resource, true, mentionsSecret) : allow("kubectl get auto-allowed", sub, resource, mentionsSecret);
  }
  if (sub === "rollout") {
    const sub2 = operands[0];
    return sub2 && KUBECTL_ROLLOUT_ALLOW.has(sub2)
      ? allow(`kubectl rollout ${sub2} auto-allowed (read-only)`, sub, auditResource, mentionsSecret)
      : defer(sub, auditResource, false, mentionsSecret);
  }
  if (sub === "config") return operands[0] === "get-contexts"
    ? allow("kubectl config get-contexts auto-allowed (read-only, no credentials)", sub, auditResource, mentionsSecret)
    : defer(sub, auditResource, false, mentionsSecret);
  if (sub === "auth") return operands[0] && KUBECTL_AUTH_ALLOW.has(operands[0])
    ? allow(`kubectl auth ${operands[0]} auto-allowed (read-only)`, sub, auditResource, mentionsSecret)
    : defer(sub, auditResource, false, mentionsSecret);
  if (sub === "plugin") return operands[0] === "list"
    ? allow("kubectl plugin list auto-allowed (read-only)", sub, auditResource, mentionsSecret)
    : defer(sub, auditResource, false, mentionsSecret);
  return defer(sub, auditResource, false, mentionsSecret);
}

export function kubectlResourceType(resource: string): string {
  return resource.split("/", 1)[0]!.split(".", 1)[0]!.toLowerCase();
}

export function isProtectedKubectlResource(resource: string): boolean {
  return KUBECTL_PROTECTED_TYPES.has(kubectlResourceType(resource));
}

export function kubectlResourceOperandsRequireReview(operands: readonly string[]): boolean {
  const [first, ...remaining] = operands;
  if (!first) return false;
  if (!first.includes("/") && remaining.some((operand) => operand.includes("/"))) return true;
  const resources = first.includes("/") ? operands : [first];
  return resources.some((resource) => resource.split(",").some(isProtectedKubectlResource));
}

function knownArguments(arguments_: readonly ResolvedWord[]): readonly string[] | undefined {
  return arguments_.every((argument) => argument.kind === "known")
    ? arguments_.map((argument) => argument.value)
    : undefined;
}

function positionalArgs(args: readonly string[], start: number): string[] {
  const positionals: string[] = [];
  for (let index = start; index < args.length;) {
    const argument = args[index]!;
    if (!argument.startsWith("-")) {
      positionals.push(argument);
      index++;
    } else if (!argument.includes("=") && KUBECTL_FLAGS_WITH_VALUES.has(argument)) {
      index += 2;
    } else index++;
  }
  return positionals;
}

/** Finds the first non-flag token after consuming global flags in any order. */
function findSubcommandIndex(args: readonly string[]): number | undefined {
  for (let index = 0; index < args.length;) {
    const argument = args[index]!;
    if (!argument.startsWith("-")) return index;
    index += !argument.includes("=") && KUBECTL_FLAGS_WITH_VALUES.has(argument) ? 2 : 1;
  }
  return undefined;
}

function resourceType(resource: string): string {
  return kubectlResourceType(resource.split(",", 1)[0]!.split("=", 1)[0]!);
}

function mentionsSecretResource(value: string): boolean {
  return /(^|[/,])secrets?(?:$|[/,])|view-secret/.test(value);
}

function evidence(decision: PolicyEvidence["decision"], subcommand: string | null, resource: string | null, secretReview: boolean, mentionsSecret: boolean, reason?: string): PolicyEvidence {
  return Object.freeze({
    name: "kubectl",
    decision,
    ...(reason ? { reason } : {}),
    kubectl: Object.freeze({ subcommand, resource, secretReview, mentionsSecret }),
  });
}

function allow(reason: string, subcommand: string | null, resource: string | null, mentionsSecret: boolean): KubectlInvocationDecision {
  return Object.freeze({ kind: "allow", reason, evidence: evidence("allow", subcommand, resource, false, mentionsSecret, reason) });
}

function deny(reason: string, subcommand: string | null, resource: string | null, mentionsSecret: boolean): KubectlInvocationDecision {
  return Object.freeze({ kind: "deny", reason, evidence: evidence("deny", subcommand, resource, false, mentionsSecret, reason) });
}

function defer(subcommand: string | null, resource: string | null, secretReview: boolean, mentionsSecret = false): KubectlInvocationDecision {
  return Object.freeze({ kind: "defer", evidence: evidence("defer", subcommand, resource, secretReview, mentionsSecret) });
}
