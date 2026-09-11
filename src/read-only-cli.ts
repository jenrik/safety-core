// Parsed read-only command profiles for CLI tools whose native permission
// patterns cannot safely distinguish subcommands from shell syntax.

import { isBashParserInitialized, parseBash, type SimpleCommand } from "./shell.js";
import { isSecretPath } from "./secrets.js";

export type ReadOnlyCliDecision =
  | { kind: "allow"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

const SHELL_SYNTAX = /[;&|<>`$(){}'"\\*?\[\]~]/;

const GH_TOP_LEVEL_COMMANDS = new Set([
  "alias", "agent", "agent-task", "agent-tasks", "agents", "attestation", "at",
  "auth", "browse", "cache", "codespace", "completion", "cs", "discussion",
  "extension", "ext", "extensions", "gist", "gpg-key", "help", "issue", "label",
  "licenses", "org", "pr", "project", "release", "repo", "ruleset", "rs", "run",
  "search", "secret", "skill", "skills", "ssh-key", "status", "variable", "version",
  "workflow",
]);


const GH_CREDENTIAL_SAFE_COMMANDS = new Set([
  "alias:list", "alias:ls", "auth:status", "cache:list", "cache:ls",
  "extension:list", "extension:ls", "extension:search", "ext:list", "ext:ls", "ext:search",
  "extensions:list", "extensions:ls", "extensions:search", "gpg-key:list", "gpg-key:ls",
  "label:list", "label:ls", "org:list", "project:field-list", "project:item-list",
  "project:list", "project:ls", "project:view", "repo:list", "repo:ls", "repo:view",
  "ruleset:check", "ruleset:list", "ruleset:ls", "ruleset:view", "rs:check", "rs:list",
  "rs:ls", "rs:view", "search:code", "search:commits", "search:issues", "search:prs",
  "search:repos", "ssh-key:list", "ssh-key:ls", "workflow:list", "workflow:ls", "workflow:view",
]);

const HELM_CREDENTIAL_SAFE_COMMANDS = new Set([
  "completion", "env", "lint", "repo:list", "search:hub", "search:repo", "show:chart",
  "show:crds", "show:readme", "show:values", "verify", "version",
]);

/**
 * Credential-safe native CLI profiles.  These intentionally accept no flags:
 * many otherwise read-only CLIs use flags for credentials, output files,
 * arbitrary code, or alternate configuration.  Users can still approve an
 * uncommon safe form through the harness' regular permission flow.
 */
const STRICT_READ_ONLY_COMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  argocd: new Set(["account:can-i", "account:get", "account:get-user-info", "account:list", "app:list", "appset:list", "cluster:list", "proj:list", "proj:role:list", "repo:list", "version"]),
  cosign: new Set(["env", "tree", "verify", "verify-attestation", "verify-blob", "verify-blob-attestation", "version"]),
  crane: new Set(["catalog", "config", "digest", "ls", "manifest", "validate", "version"]),
  docker: new Set(["config:ls", "context:ls", "image:ls", "images", "info", "network:ls", "node:ls", "plugin:ls", "search", "secret:ls", "service:ls", "stack:ls", "system:df", "version", "volume:ls"]),
  jf: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]),
  jfrog: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]),
  kubectl: new Set(["api-resources", "api-versions", "auth:can-i", "auth:whoami", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "version"]),
  nix: new Set(["hash:file", "hash:path", "hash:to-base16", "hash:to-base32", "hash:to-base64", "help-stores", "nar:ls", "path-info", "store:ping", "store:verify", "version", "why-depends"]),
  "nix-env": new Set(["version"]),
  "nix-store": new Set(["version"]),
  oc: new Set(["api-resources", "api-versions", "auth:can-i", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "projects", "version", "whoami"]),
  podman: new Set(["artifact:ls", "diff", "history", "image:ls", "images", "info", "network:ls", "pod:ls", "port", "search", "secret:ls", "system:connection:ls", "system:connection:list", "system:df", "version", "volume:ls"]),
  "podman-compose": new Set(["images", "port", "ps", "version"]),
  skopeo: new Set(["inspect", "list-tags", "manifest-digest", "standalone-verify", "version"]),
  tofu: new Set(["graph", "providers", "providers:schema", "validate", "version"]),
  npm: new Set(["explain", "help-search", "info", "list", "ll", "ls", "outdated", "prefix", "query", "root", "search", "view"]),
  pip: new Set(["check", "freeze", "inspect", "list", "show", "version"]),
  uv: new Set(["cache:dir", "cache:size", "check", "help", "pip:check", "pip:freeze", "pip:list", "pip:show", "pip:tree", "python:dir", "python:find", "python:list", "self:version", "tool:dir", "tool:list", "tree", "version", "workspace:dir", "workspace:list", "workspace:metadata"]),
  yarn: new Set(["explain", "explain:peer-requirements", "info", "npm:info", "npm:tag:list", "plugin:list", "plugin:runtime", "why", "workspaces:list"]),
};

/** Analyze one strict, credential-safe CLI profile by executable name. */
export function analyzeStrictReadOnlyCommand(command: string, executable: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, executable);
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (args.some((arg) => !arg.startsWith("-") && isSecretPath(arg))) return { kind: "defer" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version" || args[0] === "version")) return allow(executable);
  if (args.some((arg) => arg.startsWith("-"))) return { kind: "defer" };

  const allowed = STRICT_READ_ONLY_COMMANDS[executable];
  if (!allowed) return { kind: "ignore" };
  const path = strictCommandPath(args, allowed);
  if (!path) return { kind: "defer" };
  if (path === "version" && args.length !== 1) return { kind: "defer" };
  if ((executable === "kubectl" || executable === "oc") && path === "get") {
    const resource = args[1]?.split(",").map((value) => value.split("/")[0].toLowerCase()) ?? [];
    if (resource.length === 0 || resource.some((value) =>
      ["secret", "secrets", "serviceaccount", "serviceaccounts", "tokenrequest", "tokenrequests"].includes(value))) {
      return { kind: "defer" };
    }
  }
  return allow(executable);
}

function strictCommandPath(args: readonly string[], allowed: ReadonlySet<string>): string | undefined {
  for (const value of allowed) {
    const tokens = value.split(":");
    if (tokens.every((token, index) => args[index] === token)) return value;
  }
  return undefined;
}

/** Auto-allow only documented `gh` reads; all other forms retain native prompts. */
export function analyzeGhReadOnlyCommand(command: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, "gh");
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (firstGhSubcommand(args) === "api") return { kind: "ignore" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version")) return allow("gh");
  if (args.some((arg) => arg.startsWith("-"))) return { kind: "defer" };

  const path = ghPath(args);
  if (!path) return { kind: "defer" };
  if (["help", "completion", "licenses", "status"].includes(path.value)) return allow("gh");
  return GH_CREDENTIAL_SAFE_COMMANDS.has(path.value) ? allow("gh") : { kind: "defer" };
}

/** Auto-allow Helm inspection, rendering, and validation commands only. */
export function analyzeHelmReadOnlyCommand(command: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, "helm");
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version")) return allow("helm");
  if (args.some((arg) => arg.startsWith("-"))) return { kind: "defer" };
  const path = commandPath(args);
  if (!path) return { kind: "defer" };
  return (path.value === "help" || path.value.startsWith("help:") || path.value.startsWith("completion:") ||
    HELM_CREDENTIAL_SAFE_COMMANDS.has(path.value)) ? allow("helm") : { kind: "defer" };
}

function parseStandaloneLiteralCommand(command: string, executable: string):
  | { kind: "command"; command: SimpleCommand }
  | { kind: "other" }
  | { kind: "unsafe" } {
  if (!isBashParserInitialized() || !command.trim()) return { kind: "unsafe" };
  if (SHELL_SYNTAX.test(command)) return { kind: "unsafe" };
  const commands = parseBash(command);
  if (commands.length !== 1) return { kind: "unsafe" };
  return commands[0].name === executable ? { kind: "command", command: commands[0] } : { kind: "other" };
}

function ghPath(args: readonly string[]): { value: string; remaining: string[] } | undefined {
  const tokens = commandTokens(args, GH_GLOBAL_FLAGS_WITH_VALUE);
  const topLevel = tokens[0];
  if (!topLevel || !GH_TOP_LEVEL_COMMANDS.has(topLevel)) return undefined;
  if (["browse", "completion", "help", "licenses", "status", "version"].includes(topLevel)) {
    return { value: topLevel, remaining: tokens.slice(1) };
  }
  const second = tokens[1];
  if (!second) return undefined;
  if (topLevel === "repo" && ["autolink", "deploy-key", "gitignore", "license"].includes(second)) {
    const third = tokens[2];
    return third ? { value: `${topLevel}:${second}:${third}`, remaining: tokens.slice(3) } : undefined;
  }
  return { value: `${topLevel}:${second}`, remaining: tokens.slice(2) };
}

function firstGhSubcommand(args: readonly string[]): string | undefined {
  return commandTokens(args, GH_GLOBAL_FLAGS_WITH_VALUE)[0];
}

function commandPath(args: readonly string[]): { root: string; value: string } | undefined {
  const tokens = commandTokens(args, HELM_GLOBAL_FLAGS_WITH_VALUE);
  if (!tokens[0]) return undefined;
  return { root: tokens[0], value: tokens[1] ? `${tokens[0]}:${tokens[1]}` : tokens[0] };
}

const GH_GLOBAL_FLAGS_WITH_VALUE = new Set(["-R", "--repo", "--hostname"]);
const HELM_GLOBAL_FLAGS_WITH_VALUE = new Set([
  "--burst-limit", "--kube-apiserver", "--kube-as-group", "--kube-as-user", "--kube-ca-file",
  "--kube-context", "--kube-insecure-skip-tls-verify", "--kube-tls-server-name", "--kube-token",
  "--kubeconfig", "--namespace", "-n", "--qps", "--registry-config", "--repository-cache",
  "--repository-config", "--time-burst-limit", "--timeout", "--username", "--password",
]);

function commandTokens(args: readonly string[], valueFlags: ReadonlySet<string>): string[] {
  const tokens: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") {
      tokens.push(...args.slice(index + 1));
      break;
    }
    if (valueFlags.has(arg)) {
      index++;
      continue;
    }
    if ([...valueFlags].some((flag) => arg.startsWith(`${flag}=`) || (flag.length === 2 && arg.startsWith(flag) && arg.length > 2))) continue;
    if (arg.startsWith("-")) continue;
    tokens.push(arg);
  }
  return tokens;
}

function sameArguments(args: readonly string[], expected: readonly string[]): boolean {
  return args.length === expected.length && args.every((arg, index) => arg === expected[index]);
}

function allow(tool: string): ReadOnlyCliDecision {
  return { kind: "allow", reason: `${tool} auto-allowed by the read-only profile` };
}
