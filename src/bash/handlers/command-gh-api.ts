import { ignorePolicy, observePolicy, type PolicyObserver } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { policyDeny, policyIndeterminate } from "../outcome.js";
import { analyzeGhApiInvocation } from "../policies/gh-api.js";
import { GH_API_DEFER_ENVIRONMENT_NAMES } from "../policy-environment.js";
import { isKnownGhTopLevel } from "./gh-command-line.js";
import { findResolvedSubcommand, findSubcommand, knownArguments } from "./gh-utils.js";
import { hasDisabledGhPager, hasInheritedExecutableFunction, hasUnsafeGhEnvironmentBinding } from "./read-only-utils.js";

export const ghApiHandler: PolicyObserver = Object.freeze({
  name: "gh",
  observe(cursor, context) {
    const args = knownArguments(cursor);
    if (!args) {
      const subcommand = findResolvedSubcommand(cursor.invocation.argv);
      if (!subcommand) return ignorePolicy();
      if (subcommand.kind === "known" && subcommand.name !== "api") {
        return isOpaqueGhRoute(subcommand.name) ? unresolvedGhApiRoute(context) : ignorePolicy();
      }
      if (subcommand.kind === "unknown") {
        return observePolicy(policyIndeterminate(context.span, analyzeGhApiInvocation({
          endpoint: undefined,
          explicitMethod: undefined,
          hasParametersOrBody: false,
          unsafeOrMalformed: true,
        }).evidence));
      }
      if (cursor.invocation.argv.some((argument) => argument.kind === "unknown" && argument.reason.githubGraphqlEndpoint)) {
        return deniedGraphql(context);
      }
      const conservative = cursor.invocation.argv.map((argument) => argument.kind === "known" ? argument.value : "safety-core-unresolved-argument");
      const api = parseGhApiArguments(conservative, subcommand.index);
      const decision = analyzeGhApiInvocation({
        endpoint: api.endpoint,
        explicitMethod: api.explicitMethod,
        hasParametersOrBody: api.hasParametersOrBody,
        methodAmbiguous: api.methodAmbiguous || hasUnresolvedMethodValue(cursor.invocation.argv),
        unsafeOrMalformed: true,
      });
      return observePolicy(decision.kind === "deny"
        ? policyDeny(context.span, decision.evidence)
        : policyIndeterminate(context.span, decision.evidence));
    }
    const subcommand = findSubcommand(args);
    if (!subcommand) return ignorePolicy();
    if (subcommand.name !== "api") return isOpaqueGhRoute(subcommand.name) ? unresolvedGhApiRoute(context) : ignorePolicy();
    const api = parseGhApiArguments(args, subcommand.index);
    const executable = cursor.invocation.executable;
    const assignmentWrites = cursor.invocation.assignmentPatch.writes;
    const decision = analyzeGhApiInvocation({
      endpoint: api.endpoint,
      explicitMethod: api.explicitMethod,
      hasParametersOrBody: api.hasParametersOrBody,
      methodAmbiguous: api.methodAmbiguous,
      unsafeOrMalformed: api.unsafeOrMalformed
        || (executable?.kind === "known" && executable.value.includes("/"))
        || [...assignmentWrites].some((name) => name !== "GH_PAGER")
        || cursor.invocation.redirects.length > 0
        || hasInheritedExecutableFunction(cursor, "gh")
        || !hasDisabledGhPager(cursor)
        || hasUnsafeGhEnvironmentBinding(cursor, GH_API_DEFER_ENVIRONMENT_NAMES),
    });
    return observePolicy(decision.kind === "allow" ? policyIndeterminate(context.span, Object.freeze({
      ...decision.evidence,
      decision: "defer" as const,
      reason: "gh api remains prompt-gated because GitHub CLI startup state is mutable",
    }))
      : decision.kind === "deny" ? policyDeny(context.span, decision.evidence)
      : policyIndeterminate(context.span, decision.evidence));
  },
});

function isOpaqueGhRoute(name: string): boolean {
  return !isKnownGhTopLevel(name) || ["alias", "extension", "ext", "extensions"].includes(name);
}

function unresolvedGhApiRoute(context: Parameters<PolicyObserver["observe"]>[1]) {
  return observePolicy(policyIndeterminate(context.span, analyzeGhApiInvocation({
    endpoint: undefined,
    explicitMethod: undefined,
    hasParametersOrBody: false,
    unsafeOrMalformed: true,
  }).evidence));
}

function deniedGraphql(context: Parameters<PolicyObserver["observe"]>[1]) {
  const decision = analyzeGhApiInvocation({ endpoint: "graphql", explicitMethod: "GET", hasParametersOrBody: false });
  if (decision.kind !== "deny") throw new Error("GraphQL endpoint must be denied");
  return observePolicy(policyDeny(context.span, decision.evidence));
}

function hasUnresolvedMethodValue(args: readonly ResolvedWord[]): boolean {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument?.kind !== "known") continue;
    if ((argument.value === "-X" || argument.value === "--method") && args[index + 1]?.kind !== "known") return true;
  }
  return false;
}

interface ParsedGhApiArguments {
  readonly endpoint: string | undefined;
  readonly explicitMethod: string | undefined;
  readonly hasParametersOrBody: boolean;
  readonly methodAmbiguous: boolean;
  readonly unsafeOrMalformed: boolean;
}

const UNSAFE_VALUE_OPTIONS = new Set([
  "--hostname", "--input", "-H", "--header", "--cache", "-p", "--preview", "-q", "--jq", "-t", "--template",
]);
const UNSAFE_BOOLEAN_OPTIONS = new Set([
  "-i", "--include", "--paginate", "--slurp", "--silent", "--verbose", "--allow-escape-sequences",
]);

export function parseGhApiArguments(args: readonly string[], apiIndex: number): ParsedGhApiArguments {
  const endpoints: string[] = [];
  const methods: string[] = [];
  let hasParametersOrBody = false;
  let unsafeOrMalformed = apiIndex !== 0;

  for (let index = 0; index < args.length; index++) {
    if (index === apiIndex) continue;
    const argument = args[index]!;
    if (!argument.startsWith("-") || argument === "-") {
      endpoints.push(argument);
      continue;
    }
    if (argument === "--") {
      unsafeOrMalformed = true;
      continue;
    }

    const short = parseApiShortOptions(args, index, argument);
    if (short) {
      if (short.method !== undefined) methods.push(short.method);
      hasParametersOrBody ||= short.hasParametersOrBody;
      unsafeOrMalformed ||= short.unsafeOrMalformed;
      index = short.lastIndex;
      continue;
    }

    const method = optionValue(args, index, argument, "-X", "--method");
    if (method) {
      if (!method.value) unsafeOrMalformed = true;
      else methods.push(method.value);
      index = method.lastIndex;
      continue;
    }

    const rawField = optionValue(args, index, argument, "-f", "--raw-field");
    if (rawField) {
      hasParametersOrBody = true;
      if (!validField(rawField.value)) unsafeOrMalformed = true;
      index = rawField.lastIndex;
      continue;
    }

    const typedField = optionValue(args, index, argument, "-F", "--field");
    if (typedField) {
      hasParametersOrBody = true;
      if (!validField(typedField.value) || typedField.value.slice(typedField.value.indexOf("=") + 1).startsWith("@")) unsafeOrMalformed = true;
      index = typedField.lastIndex;
      continue;
    }

    const unsafeValue = [...UNSAFE_VALUE_OPTIONS].find((option) => argument === option || argument.startsWith(`${option}=`)
      || (option.length === 2 && argument.startsWith(option) && argument.length > 2));
    if (unsafeValue) {
      unsafeOrMalformed = true;
      if (unsafeValue === "--input") hasParametersOrBody = true;
      if (argument === unsafeValue) index++;
      continue;
    }
    if (UNSAFE_BOOLEAN_OPTIONS.has(argument)) {
      unsafeOrMalformed = true;
      continue;
    }
    unsafeOrMalformed = true;
  }

  return Object.freeze({
    endpoint: endpoints.length === 1 ? endpoints[0] : undefined,
    explicitMethod: methods.at(-1),
    hasParametersOrBody,
    methodAmbiguous: false,
    unsafeOrMalformed: unsafeOrMalformed || endpoints.length !== 1,
  });
}

function parseApiShortOptions(args: readonly string[], index: number, argument: string): {
  readonly method?: string;
  readonly hasParametersOrBody: boolean;
  readonly unsafeOrMalformed: boolean;
  readonly lastIndex: number;
} | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument === "-") return undefined;
  const options = argument.slice(1);
  let unsafeOrMalformed = false;
  for (let offset = 0; offset < options.length; offset++) {
    const option = options[offset]!;
    if (option === "i") {
      unsafeOrMalformed = true;
      continue;
    }
    if (!["X", "f", "F", "H", "p", "q", "t"].includes(option)) {
      return { hasParametersOrBody: false, unsafeOrMalformed: true, lastIndex: index };
    }
    const attached = options.slice(offset + 1).replace(/^=/, "");
    const separate = attached.length === 0;
    const next = separate ? args[index + 1] : undefined;
    const value = separate && next && !next.startsWith("-") ? next : attached;
    const lastIndex = separate ? index + 1 : index;
    if (!value) return { hasParametersOrBody: option === "f" || option === "F", unsafeOrMalformed: true, lastIndex };
    if (option === "X") return { method: value, hasParametersOrBody: false, unsafeOrMalformed, lastIndex };
    if (option === "f") return { hasParametersOrBody: true, unsafeOrMalformed: unsafeOrMalformed || !validField(value), lastIndex };
    if (option === "F") {
      return {
        hasParametersOrBody: true,
        unsafeOrMalformed: unsafeOrMalformed || !validField(value) || value.slice(value.indexOf("=") + 1).startsWith("@"),
        lastIndex,
      };
    }
    return { hasParametersOrBody: false, unsafeOrMalformed: true, lastIndex };
  }
  return { hasParametersOrBody: false, unsafeOrMalformed, lastIndex: index };
}

function optionValue(
  args: readonly string[],
  index: number,
  argument: string,
  short: string,
  long: string,
): { readonly value: string; readonly lastIndex: number } | undefined {
  if (argument === short || argument === long) {
    const value = args[index + 1];
    return { value: value && !value.startsWith("-") ? value : "", lastIndex: index + 1 };
  }
  if (argument.startsWith(`${long}=`)) return { value: argument.slice(long.length + 1), lastIndex: index };
  if (argument.startsWith(`${short}=`)) return { value: argument.slice(short.length + 1), lastIndex: index };
  if (argument.startsWith(short) && argument.length > short.length) return { value: argument.slice(short.length), lastIndex: index };
  return undefined;
}

function validField(value: string): boolean {
  const equals = value.indexOf("=");
  return equals > 0;
}
