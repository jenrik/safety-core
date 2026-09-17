import { ignorePolicy, observePolicy, type PolicyObservation, type PolicyObserver, type InvocationCursor } from "../dispatch.js";
import { hasBinding, lookupBinding, type Environment } from "../environment.js";
import { indeterminate, policyIndeterminate, policySafe, type Outcome } from "../outcome.js";
import {
  BASH_FUNCTIONS_CAPTURED_FACT,
  GH_DEFER_ENVIRONMENT_NAMES,
  GH_INHERITED_PAGER_FACT,
  inheritedBashFunctionFact,
} from "../policy-environment.js";
import { isSecretPath, readOnlyAllow, readOnlyDefer, type AllowedFlag, type ReadOnlyInvocationDecision } from "../policies/read-only.js";

export type ReadOnlyPolicy = "generic-read-only" | "gh-read-only" | "helm-read-only" | "strict-read-only";

const UNSAFE_CONFIGURATION_BINDINGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  docker: ["DOCKER_CONFIG"],
  git: ["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "PAGER"],
  kubectl: ["KUBECONFIG"],
  oc: ["KUBECONFIG"],
});

export function readOnlyHandler(
  name: string,
  policy: ReadOnlyPolicy,
  analyze: (args: readonly string[]) => ReadOnlyInvocationDecision | { readonly kind: "ignore" },
): PolicyObserver {
  return Object.freeze({
    name,
    observe(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return observePolicy(policyIndeterminate(context.span, defer(policy, name).evidence));
      const decision = analyze(args);
      if (decision.kind === "ignore") return ignorePolicy();
      const executable = cursor.invocation.executable;
      if (executable?.kind === "known" && executable.value.includes("/")) {
        return observePolicy(policyIndeterminate(context.span, defer(policy, name).evidence));
      }
      if (cursor.invocation.assignmentPatch.writes.size > 0 || cursor.invocation.redirects.length > 0) {
        return observePolicy(policyIndeterminate(context.span, defer(policy, name).evidence));
      }
      if (hasInheritedExecutableFunction(cursor, name)
        || (name === "gh" ? hasUnsafeGhEnvironmentBinding(cursor) : hasUnsafeConfigurationBinding(cursor, name))) {
        return observePolicy(policyIndeterminate(context.span, defer(policy, name).evidence));
      }
      return observePolicy(decision.kind === "allow" ? policySafe(decision.evidence) : policyIndeterminate(context.span, decision.evidence));
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

/** Defer when gh behavior can be redirected by inherited or shell-assigned state. */
export function hasUnsafeGhEnvironmentBinding(
  cursor: InvocationCursor,
  names: readonly string[] = GH_DEFER_ENVIRONMENT_NAMES,
): boolean {
  const environment = cursor.invocation.environment;
  for (const name of names) {
    if (name === GH_INHERITED_PAGER_FACT) continue;
    if (name === "PAGER") {
      if (hasBinding(environment, "PAGER")) {
        if (bindingIsUnsafe(environment, "PAGER")) return true;
      } else if (bindingIsUnsafe(environment, GH_INHERITED_PAGER_FACT)) return true;
      continue;
    }
    if (bindingIsUnsafe(environment, name)) return true;
  }
  return false;
}

/** An explicit empty or `cat` GH_PAGER overrides both mutable config and PAGER. */
export function hasDisabledGhPager(cursor: InvocationCursor): boolean {
  const environment = cursor.invocation.environment;
  if (!hasBinding(environment, "GH_PAGER")) return false;
  const binding = lookupBinding(environment, "GH_PAGER");
  return binding.exported && binding.value.kind === "known" && (binding.value.value === "" || binding.value.value === "cat");
}

/** GitHub CLI treats any present GH_PROMPT_DISABLED value as disabling prompts. */
export function hasDisabledGhPrompts(cursor: InvocationCursor): boolean {
  const environment = cursor.invocation.environment;
  if (!hasBinding(environment, "GH_PROMPT_DISABLED")) return false;
  const binding = lookupBinding(environment, "GH_PROMPT_DISABLED");
  return binding.exported && binding.value.kind === "known";
}

export function readOnlyStraceObservation(_cursor: InvocationCursor, span: Parameters<PolicyObserver["observe"]>[1]["span"]): PolicyObservation {
  return observePolicy(policyIndeterminate(span, defer("generic-read-only", "strace").evidence));
}

/** Imported Bash functions can replace an audited executable before process lookup. */
export function hasInheritedExecutableFunction(cursor: InvocationCursor, executable: string): boolean {
  const environment = cursor.invocation.environment;
  if (hasBinding(environment, inheritedBashFunctionFact(executable))) return true;
  if (!hasBinding(environment, BASH_FUNCTIONS_CAPTURED_FACT)) return environment.missingBindings === "unknown";
  const captured = lookupBinding(environment, BASH_FUNCTIONS_CAPTURED_FACT);
  return !captured.exported || captured.value.kind !== "known";
}

function hasUnsafeConfigurationBinding(cursor: InvocationCursor, executable: string): boolean {
  return (UNSAFE_CONFIGURATION_BINDINGS[executable] ?? []).some((name) => {
    const value = lookupBinding(cursor.invocation.environment, name).value;
    return value.kind === "unknown" || (value.kind === "known" && value.value.length > 0);
  });
}

function bindingIsUnsafe(environment: Environment, name: string): boolean {
  if (!hasBinding(environment, name)) return environment.missingBindings === "unknown";
  const value = lookupBinding(environment, name).value;
  return value.kind === "unknown" || (value.kind === "known" && value.value.length > 0);
}
