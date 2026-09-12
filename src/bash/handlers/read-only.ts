import type { CommandHandler, InvocationCursor } from "../dispatch.js";
import { lookupBinding } from "../environment.js";
import { indeterminate, policyIndeterminate, policySafe } from "../outcome.js";
import { kubectlResourceOperandsRequireReview } from "../policies/kubectl.js";
import {
  GH_ALLOWED_FLAGS,
  GH_CREDENTIAL_SAFE_COMMANDS,
  GH_GLOBAL_FLAGS_WITH_VALUE,
  GH_TOP_LEVEL_COMMANDS,
  HELM_CREDENTIAL_SAFE_COMMANDS,
  STRICT_ALLOWED_FLAGS,
  STRICT_READ_ONLY_COMMANDS,
  isSecretPath,
  readOnlyAllow,
  readOnlyDefer,
  type AllowedFlag,
  type ReadOnlyInvocationDecision,
} from "../policies/read-only.js";

const CREDENTIAL_CONFIGURATION_BINDINGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  gh: ["GH_CONFIG_DIR"],
  docker: ["DOCKER_CONFIG"],
  kubectl: ["KUBECONFIG"],
  oc: ["KUBECONFIG"],
});

const ghReadOnlyHandler: CommandHandler = handler("gh", (args) => {
  if (firstGhSubcommand(args) === "api") return { kind: "ignore" };
  if (hasSecretOperand(args)) return defer("gh-read-only", "gh");
  if (args.length === 1 && ["--help", "--version"].includes(args[0]!)) return allow("gh-read-only", "gh");
  const positionals = parseAllowedFlags(args, GH_ALLOWED_FLAGS);
  if (!positionals) return defer("gh-read-only", "gh");
  const path = ghPath(positionals);
  if (!path || !ghOperandsAreAudited(path.value, path.remaining)) return defer("gh-read-only", "gh");
  return ["help", "completion", "licenses", "status"].includes(path.value) || GH_CREDENTIAL_SAFE_COMMANDS.has(path.value)
    ? allow("gh-read-only", "gh") : defer("gh-read-only", "gh");
});

const helmReadOnlyHandler: CommandHandler = handler("helm", (args) => {
  if (hasSecretOperand(args)) return defer("helm-read-only", "helm");
  if (args.length === 1 && ["--help", "--version"].includes(args[0]!)) return allow("helm-read-only", "helm");
  if (args.some((argument) => argument.startsWith("-"))) return defer("helm-read-only", "helm");
  const [root, second] = args;
  if (!root) return defer("helm-read-only", "helm");
  if (root === "help") return allow("helm-read-only", "helm");
  if (root === "completion") return args.length === 2 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  if (root === "verify") return args.length >= 2 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  const path = second ? `${root}:${second}` : root;
  if (["show:chart", "inspect:chart"].includes(path)) return args.length === 3 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  return HELM_CREDENTIAL_SAFE_COMMANDS.has(path) ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
});

function strictReadOnlyHandler(executable: string): CommandHandler {
  return handler(executable, (args) => {
    if (hasSecretOperand(args)) return defer("strict-read-only", executable);
    if (args.length === 1 && ["--help", "--version", "version"].includes(args[0]!)) return allow("strict-read-only", executable);
    const positionals = parseAllowedFlags(args, STRICT_ALLOWED_FLAGS[executable] ?? []);
    if (!positionals) return defer("strict-read-only", executable);
    const allowed = STRICT_READ_ONLY_COMMANDS[executable]!;
    const path = strictPath(positionals, allowed);
    if (!path || (path === "version" && positionals.length !== 1)) return defer("strict-read-only", executable);
    if (["kubectl", "oc"].includes(executable) && path === "get") {
      const resources = positionals.slice(1);
      if (resources.length === 0 || kubectlResourceOperandsRequireReview(resources)) return defer("strict-read-only", executable);
    }
    return allow("strict-read-only", executable);
  });
}

function handler(name: string, analyze: (args: readonly string[]) => ReadOnlyInvocationDecision | { readonly kind: "ignore" }): CommandHandler {
  return Object.freeze({
    name,
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return policyIndeterminate(context.span, defer(policyName(name), name).evidence);
      const executable = cursor.invocation.executable;
      if (executable?.kind === "known" && executable.value.includes("/")) {
        return policyIndeterminate(context.span, defer(policyName(name), name).evidence);
      }
      if (cursor.invocation.assignmentPatch.writes.size > 0 || cursor.invocation.redirects.length > 0) {
        return policyIndeterminate(context.span, defer(policyName(name), name).evidence);
      }
      if (hasCredentialConfigurationBinding(cursor, name)) {
        return policyIndeterminate(context.span, defer(policyName(name), name).evidence);
      }
      const decision = analyze(args);
      if (decision.kind === "ignore") return indeterminate(context.span);
      return decision.kind === "allow" ? policySafe(decision.evidence) : policyIndeterminate(context.span, decision.evidence);
    },
  });
}

function policyName(name: string): "gh-read-only" | "helm-read-only" | "strict-read-only" {
  return name === "gh" ? "gh-read-only" : name === "helm" ? "helm-read-only" : "strict-read-only";
}

function knownArguments(cursor: InvocationCursor): string[] | undefined {
  return cursor.invocation.argv.every((argument) => argument.kind === "known")
    ? cursor.invocation.argv.map((argument) => argument.value)
    : undefined;
}

/**
 * A non-empty known or unknown explicit config binding can redirect a reviewed
 * CLI to credentials. Only the binding state is inspected; its value never
 * enters evidence or diagnostics.
 */
function hasCredentialConfigurationBinding(cursor: InvocationCursor, executable: string): boolean {
  return (CREDENTIAL_CONFIGURATION_BINDINGS[executable] ?? []).some((name) => {
    const value = lookupBinding(cursor.invocation.environment, name).value;
    return value.kind === "unknown" || (value.kind === "known" && value.value.length > 0);
  });
}

function allow(name: "gh-read-only" | "helm-read-only" | "strict-read-only", tool: string): ReadOnlyInvocationDecision {
  return readOnlyAllow(name, tool);
}

function defer(name: "gh-read-only" | "helm-read-only" | "strict-read-only", tool: string): ReadOnlyInvocationDecision {
  return readOnlyDefer(name, tool);
}

function hasSecretOperand(args: readonly string[]): boolean {
  return args.some((argument) => !argument.startsWith("-") && isSecretPath(argument));
}

function parseAllowedFlags(args: readonly string[], specs: readonly AllowedFlag[]): string[] | undefined {
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

function commandTokens(args: readonly string[], valueFlags: ReadonlySet<string>): string[] {
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

function firstGhSubcommand(args: readonly string[]): string | undefined {
  return commandTokens(args, GH_GLOBAL_FLAGS_WITH_VALUE)[0];
}

function ghPath(positionals: readonly string[]): { readonly value: string; readonly remaining: readonly string[] } | undefined {
  const tokens = commandTokens(positionals, GH_GLOBAL_FLAGS_WITH_VALUE);
  const root = tokens[0];
  if (!root || !GH_TOP_LEVEL_COMMANDS.has(root)) return undefined;
  if (["browse", "completion", "help", "licenses", "status", "version"].includes(root)) return { value: root, remaining: tokens.slice(1) };
  const second = tokens[1];
  return second ? { value: `${root}:${second}`, remaining: tokens.slice(2) } : undefined;
}

/** Only paths with reviewed positional grammars may carry extra operands. */
function ghOperandsAreAudited(path: string, remaining: readonly string[]): boolean {
  if (remaining.length === 0) return true;
  return new Set([
    "help", "completion", "extension:search", "ext:search", "extensions:search",
    "project:field-list", "project:item-list", "project:view", "search:commits", "search:issues",
    "search:prs", "search:repos", "workflow:view",
  ]).has(path);
}

function strictPath(args: readonly string[], allowed: ReadonlySet<string>): string | undefined {
  return [...allowed].sort((left, right) => right.split(":").length - left.split(":").length)
    .find((path) => path.split(":").every((token, index) => args[index] === token));
}

export const readOnlyHandlers: readonly CommandHandler[] = Object.freeze([
  ghReadOnlyHandler,
  helmReadOnlyHandler,
  ...Object.keys(STRICT_READ_ONLY_COMMANDS).map(strictReadOnlyHandler),
]);

export const ghReadOnlyHandlers: readonly CommandHandler[] = Object.freeze([ghReadOnlyHandler]);
export const helmReadOnlyHandlers: readonly CommandHandler[] = Object.freeze([helmReadOnlyHandler]);
export function strictReadOnlyHandlers(executable: string): readonly CommandHandler[] {
  return STRICT_READ_ONLY_COMMANDS[executable] ? Object.freeze([strictReadOnlyHandler(executable)]) : Object.freeze([]);
}
