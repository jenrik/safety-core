import type { BashPolicyEvent, PermissionBashPolicy, PolicyDecision } from "../../../src/policy/types.js";
import { SECRET_EXCEPTIONS, SECRET_PATTERNS } from "../../../src/patterns.js";

export type CodePermissionDefinition = Omit<PermissionBashPolicy, "source" | "evaluate"> & {
  readonly apiVersion: 1;
  evaluate(event: BashPolicyEvent): PolicyDecision;
};

export function ignore(): PolicyDecision {
  return Object.freeze({ kind: "ignore" });
}

export function defer(): PolicyDecision {
  return Object.freeze({ kind: "defer" });
}

export function allow(reason: string, event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>): PolicyDecision {
  return Object.freeze({
    kind: "allow",
    reason: Object.freeze([{ kind: "literal", value: reason }]),
    audit: Object.freeze({ invocation: event }),
  });
}

export function deny(reason: string, event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>): PolicyDecision {
  return Object.freeze({
    kind: "deny",
    reason: Object.freeze([{ kind: "literal", value: reason }]),
    audit: Object.freeze({ invocation: event }),
  });
}

export function executableIs(event: BashPolicyEvent, names: ReadonlySet<string>): event is Extract<BashPolicyEvent, { readonly kind: "invocation" }> {
  return event.kind === "invocation"
    && event.executable?.kind === "known"
    && names.has(basename(event.executable.value));
}

export function knownArguments(event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>): readonly string[] | undefined {
  return event.argv.every((argument) => argument.kind === "known")
    ? event.argv.map((argument) => argument.value)
    : undefined;
}

export function hasExplicitExecutionRoute(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  allowedAssignments: readonly string[] = [],
): boolean {
  return event.executable?.kind !== "known"
    || event.executable.value.includes("/")
    || Object.keys(event.assignments).some((name) => !allowedAssignments.includes(name))
    || event.redirects.length > 0;
}

export function hasUnsafeEnvironment(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  names: readonly string[],
): boolean {
  return names.some((name) => {
    const value = event.environment[name];
    return value === undefined
      ? event.missingBindings === "unknown"
      : value.kind === "unknown" || (value.kind === "known" && value.value.length > 0);
  });
}

export function hasPresentEnvironment(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  name: string,
): boolean {
  const value = event.environment[name];
  return value !== undefined && value.kind !== "unset";
}

export function hasKnownEnvironment(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  name: string,
): boolean {
  return event.environment[name]?.kind === "known";
}

export function hasKnownExportedEnvironment(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  name: string,
): boolean {
  return event.environment[name]?.kind === "known" && event.exportedEnvironment?.[name] === true;
}

export function hasInheritedExecutableFunction(
  event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>,
  executable: string,
): boolean {
  if (hasPresentEnvironment(event, `__SAFETY_CORE_BASH_FUNCTION_${executable}`)) return true;
  return !hasPresentEnvironment(event, "__SAFETY_CORE_BASH_FUNCTIONS_CAPTURED") && event.missingBindings === "unknown";
}

export function isSecretPath(value: string): boolean {
  const name = basename(value);
  return !!name && !SECRET_EXCEPTIONS.some((pattern) => matchesGlob(name, pattern)) && SECRET_PATTERNS.some((pattern) => matchesGlob(name, pattern));
}

function basename(path: string): string {
  return path.split("/").filter(Boolean).at(-1) ?? "";
}

function matchesGlob(value: string, pattern: string): boolean {
  const expression = `^${pattern.split("*").map(escapeRegex).join(".*")}$`;
  return new RegExp(expression, "i").test(value);
}

function escapeRegex(value: string): string {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}
