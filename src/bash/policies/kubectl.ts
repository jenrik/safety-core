import { isBindingResolvedWord, type NormalizedCommand, type ResolvedWord } from "../expand.js";
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
  if (subcommandIndex === undefined) return defer(null, null, false);
  const sub = args[subcommandIndex];
  if (!sub) return defer(null, null, false);
  const evidenceSubcommand = isBindingResolvedWord(invocation.argv[subcommandIndex]!) ? null : sub;
  const mentionsSecret = args.some(mentionsSecretResource);
  const operands = positionalArgs(args, subcommandIndex + 1);
  const firstOperand = operands[0];
  const auditResource = !firstOperand || isBindingResolvedWord(invocation.argv[firstOperand.index]!)
    ? null
    : resourceType(firstOperand.value);
  if (sub === "view-secret") return deny(
    "kubectl view-secret is blocked: it decodes and displays Secret values in plaintext.",
    evidenceSubcommand,
    auditResource,
    mentionsSecret,
  );
  if (KUBECTL_ALWAYS_ALLOW.has(sub)) return allow(
    evidenceSubcommand ? `kubectl ${sub} auto-allowed (read-only)` : "kubectl command auto-allowed (read-only)",
    evidenceSubcommand,
    auditResource,
    mentionsSecret,
  );
  if (sub === "get") {
    const resources = operands.map((operand) => operand.value);
    if (resources.length === 0) return defer(evidenceSubcommand, null, false);
    const requiresReview = kubectlResourceOperandsRequireReview(resources);
    const resource = auditResource;
    return requiresReview ? defer(evidenceSubcommand, resource, true, mentionsSecret) : allow("kubectl get auto-allowed", evidenceSubcommand, resource, mentionsSecret);
  }
  if (sub === "rollout") {
    const sub2 = operands[0]?.value;
    const literalPath = evidenceSubcommand !== null && operandIsLiteral(invocation, operands[0]);
    return sub2 && KUBECTL_ROLLOUT_ALLOW.has(sub2)
      ? allow(literalPath ? `kubectl rollout ${sub2} auto-allowed (read-only)` : "kubectl rollout command auto-allowed (read-only)", evidenceSubcommand, auditResource, mentionsSecret)
      : defer(evidenceSubcommand, auditResource, false, mentionsSecret);
  }
  if (sub === "config") return operands[0]?.value === "get-contexts"
    ? allow("kubectl config get-contexts auto-allowed (read-only, no credentials)", evidenceSubcommand, auditResource, mentionsSecret)
    : defer(evidenceSubcommand, auditResource, false, mentionsSecret);
  if (sub === "auth") return operands[0] && KUBECTL_AUTH_ALLOW.has(operands[0].value)
    ? allow(operandIsLiteral(invocation, operands[0]) && evidenceSubcommand !== null
      ? `kubectl auth ${operands[0].value} auto-allowed (read-only)`
      : "kubectl auth command auto-allowed (read-only)", evidenceSubcommand, auditResource, mentionsSecret)
    : defer(evidenceSubcommand, auditResource, false, mentionsSecret);
  if (sub === "plugin") return operands[0]?.value === "list"
    ? allow("kubectl plugin list auto-allowed (read-only)", evidenceSubcommand, auditResource, mentionsSecret)
    : defer(evidenceSubcommand, auditResource, false, mentionsSecret);
  return defer(evidenceSubcommand, auditResource, false, mentionsSecret);
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

interface PositionalArgument {
  readonly value: string;
  readonly index: number;
}

function positionalArgs(args: readonly string[], start: number): PositionalArgument[] {
  const positionals: PositionalArgument[] = [];
  for (let index = start; index < args.length;) {
    const argument = args[index]!;
    if (!argument.startsWith("-")) {
      positionals.push({ value: argument, index });
      index++;
    } else if (!argument.includes("=") && KUBECTL_FLAGS_WITH_VALUES.has(argument)) {
      index += 2;
    } else index++;
  }
  return positionals;
}

function operandIsLiteral(invocation: NormalizedCommand, operand: PositionalArgument | undefined): boolean {
  return operand !== undefined && !isBindingResolvedWord(invocation.argv[operand.index]!);
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
