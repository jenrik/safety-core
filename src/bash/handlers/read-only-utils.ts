import type { CommandHandler, InvocationCursor } from "../dispatch.js";
import { lookupBinding } from "../environment.js";
import { indeterminate, policyIndeterminate, policySafe, safe, type Outcome } from "../outcome.js";
import { isSecretPath, readOnlyAllow, readOnlyDefer, type AllowedFlag, type ReadOnlyInvocationDecision } from "../policies/read-only.js";

export type ReadOnlyPolicy = "generic-read-only" | "gh-read-only" | "helm-read-only" | "strict-read-only";

const CREDENTIAL_CONFIGURATION_BINDINGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  gh: ["GH_CONFIG_DIR"],
  docker: ["DOCKER_CONFIG"],
  kubectl: ["KUBECONFIG"],
  oc: ["KUBECONFIG"],
});

export function readOnlyHandler(
  name: string,
  policy: ReadOnlyPolicy,
  analyze: (args: readonly string[]) => ReadOnlyInvocationDecision | { readonly kind: "ignore" },
): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return policyIndeterminate(context.span, defer(policy, name).evidence);
      const executable = cursor.invocation.executable;
      if (executable?.kind === "known" && executable.value.includes("/")) {
        return policyIndeterminate(context.span, defer(policy, name).evidence);
      }
      if (cursor.invocation.assignmentPatch.writes.size > 0 || cursor.invocation.redirects.length > 0) {
        return policyIndeterminate(context.span, defer(policy, name).evidence);
      }
      if (hasCredentialConfigurationBinding(cursor, name)) {
        return policyIndeterminate(context.span, defer(policy, name).evidence);
      }
      const decision = analyze(args);
      if (decision.kind === "ignore") return indeterminate(context.span);
      return decision.kind === "allow" ? policySafe(decision.evidence) : policyIndeterminate(context.span, decision.evidence);
    },
  });
}

export function knownArguments(cursor: InvocationCursor): string[] | undefined {
  return cursor.invocation.argv.every((argument) => argument.kind === "known")
    ? cursor.invocation.argv.map((argument) => argument.value)
    : undefined;
}

export function allow(name: ReadOnlyPolicy, tool: string): ReadOnlyInvocationDecision {
  return readOnlyAllow(name, tool);
}

export function defer(name: ReadOnlyPolicy, tool: string): ReadOnlyInvocationDecision {
  return readOnlyDefer(name, tool);
}

export function hasSecretOperand(args: readonly string[]): boolean {
  return args.some((argument) => !argument.startsWith("-") && isSecretPath(argument));
}

export function parseAllowedFlags(args: readonly string[], specs: readonly AllowedFlag[]): string[] | undefined {
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

export function commandTokens(args: readonly string[], valueFlags: ReadonlySet<string>): string[] {
  const tokens: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") return [...tokens, ...args.slice(index + 1)];
    if (valueFlags.has(argument)) { index++; continue; }
    if ([...valueFlags].some((flag) => argument.startsWith(`${flag}=`) || (flag.length === 2 && argument.startsWith(flag) && argument.length > 2))) continue;
    if (!argument.startsWith("-")) tokens.push(argument);
  }
  return tokens;
}

export function hasUnsafeGitArgument(args: readonly string[]): boolean {
  return args.some((argument) => argument === "--ext-diff"
    || argument === "--textconv"
    || argument === "--no-index"
    || argument === "--output"
    || argument.startsWith("--output="));
}

export function isStraceOutputArgument(argument: string): boolean {
  return argument === "-o" || argument.startsWith("-o") || argument === "--output" || argument.startsWith("--output=");
}

export function readOnlyStraceOutcome(cursor: InvocationCursor, span: Parameters<CommandHandler["handle"]>[1]["span"]): Outcome {
  const args = knownArguments(cursor);
  return !args || cursor.invocation.redirects.length > 0 || args.some(isStraceOutputArgument)
    ? policyIndeterminate(span, defer("generic-read-only", "strace").evidence)
    : safe();
}

function hasCredentialConfigurationBinding(cursor: InvocationCursor, executable: string): boolean {
  return (CREDENTIAL_CONFIGURATION_BINDINGS[executable] ?? []).some((name) => {
    const value = lookupBinding(cursor.invocation.environment, name).value;
    return value.kind === "unknown" || (value.kind === "known" && value.value.length > 0);
  });
}
