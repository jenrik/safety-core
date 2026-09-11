// Parsed read-only command profiles for CLI tools whose native permission
// patterns cannot safely distinguish subcommands from shell syntax.

import { isBashParserInitialized, parseBash, type SimpleCommand } from "./shell.js";
import { isSecretPath } from "./secrets.js";
import { kubectlResourceOperandsRequireReview } from "./kubectl.js";

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
  "auth:status", "cache:list", "cache:ls",
  "extension:list", "extension:ls", "extension:search", "ext:list", "ext:ls", "ext:search",
  "extensions:list", "extensions:ls", "extensions:search", "gpg-key:list", "gpg-key:ls",
  "label:list", "label:ls", "org:list", "project:field-list", "project:item-list",
  "project:list", "project:ls", "project:view", "repo:list", "repo:ls",
  "ruleset:check", "ruleset:list", "ruleset:ls", "ruleset:view", "rs:check", "rs:list",
  "rs:ls", "rs:view", "search:commits", "search:issues", "search:prs",
  "search:repos", "ssh-key:list", "ssh-key:ls", "workflow:list", "workflow:ls", "workflow:view",
]);

const HELM_CREDENTIAL_SAFE_COMMANDS = new Set([
  "completion", "inspect:chart", "search:hub", "search:repo", "show:chart",
  "verify", "version",
]);

/**
 * Credential-safe native CLI profiles. Only the small set of flags audited
 * below is accepted; all other options retain the regular permission prompt.
 */
const STRICT_READ_ONLY_COMMANDS: Readonly<Record<string, ReadonlySet<string>>> = {
  argocd: new Set(["account:can-i", "account:get", "account:get-user-info", "account:list", "app:list", "appset:list", "cluster:list", "proj:list", "proj:role:list", "project:list", "project:role:list", "repo:list", "version"]),
  cosign: new Set(["tree", "verify", "verify-attestation", "verify-blob", "verify-blob-attestation", "version"]),
  crane: new Set(["catalog", "digest", "ls", "manifest", "validate", "version"]),
  docker: new Set([
    "config:list", "config:ls", "context:list", "context:ls", "image:list",
    "image:ls", "images", "info",
    "network:list", "network:ls", "node:list", "node:ls", "plugin:list", "plugin:ls",
    "search", "secret:list", "secret:ls", "service:list", "service:ls",
    "stack:list", "stack:ls", "system:df", "version", "volume:list", "volume:ls",
  ]),
  jf: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]),
  jfrog: new Set(["config:show", "options", "rt:search", "stats:rt", "version"]),
  kubectl: new Set(["api-resources", "api-versions", "auth:can-i", "auth:whoami", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "version"]),
  nix: new Set(["hash:file", "hash:path", "hash:to-base16", "hash:to-base32", "hash:to-base64", "help-stores", "nar:ls", "path-info", "store:ping", "store:verify", "version", "why-depends"]),
  "nix-env": new Set(["version"]),
  "nix-store": new Set(["version"]),
  oc: new Set(["api-resources", "api-versions", "auth:can-i", "cluster-info", "config:current-context", "config:get-contexts", "explain", "get", "plugin:list", "projects", "version", "whoami"]),
  podman: new Set(["artifact:list", "artifact:ls", "diff", "image:list", "image:ls", "images", "info", "network:list", "network:ls", "pod:list", "pod:ls", "pod:ps", "port", "search", "secret:list", "secret:ls", "system:connection:ls", "system:connection:list", "system:df", "version", "volume:list", "volume:ls"]),
  "podman-compose": new Set(["images", "port", "version"]),
  skopeo: new Set(["list-tags", "manifest-digest", "standalone-verify", "version"]),
  tofu: new Set(["version"]),
  npm: new Set(["explain", "find", "help-search", "la", "list", "ll", "ls", "outdated", "prefix", "root", "s", "se", "search", "why"]),
  pip: new Set(["check", "freeze", "inspect", "list", "show", "version"]),
  uv: new Set(["cache:dir", "cache:size", "check", "help", "pip:check", "pip:freeze", "pip:list", "pip:show", "pip:tree", "python:dir", "python:find", "python:list", "self:version", "tool:dir", "tool:list", "version", "workspace:dir", "workspace:list", "workspace:metadata"]),
  yarn: new Set(["explain", "explain:peer-requirements", "info", "npm:info", "npm:tag:list", "plugin:list", "plugin:runtime", "why", "workspaces:list"]),
};

/** Analyze one strict, credential-safe CLI profile by executable name. */
export function analyzeStrictReadOnlyCommand(command: string, executable: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, executable);
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (args.some((arg) => !arg.startsWith("-") && isSecretPath(arg))) return { kind: "defer" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version" || args[0] === "version")) return allow(executable);
  const positionals = parseAllowedFlags(args, STRICT_ALLOWED_FLAGS[executable] ?? []);
  if (!positionals) return { kind: "defer" };

  const allowed = STRICT_READ_ONLY_COMMANDS[executable];
  if (!allowed) return { kind: "ignore" };
  const path = strictCommandPath(positionals, allowed);
  if (!path) return { kind: "defer" };
  if (path === "version" && positionals.length !== 1) return { kind: "defer" };
  if ((executable === "kubectl" || executable === "oc") && path === "get") {
    const resources = positionals.slice(1);
    if (resources.length === 0 || kubectlResourceOperandsRequireReview(resources)) {
      return { kind: "defer" };
    }
  }
  return allow(executable);
}

function strictCommandPath(
  args: readonly string[],
  allowed: ReadonlySet<string>,
): string | undefined {
  for (const value of [...allowed].sort((left, right) => right.split(":").length - left.split(":").length)) {
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
  if (args.some((arg) => !arg.startsWith("-") && isSecretPath(arg))) return { kind: "defer" };
  if (firstGhSubcommand(args) === "api") return { kind: "ignore" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version")) return allow("gh");
  const positionals = parseAllowedFlags(args, GH_ALLOWED_FLAGS);
  if (!positionals) return { kind: "defer" };

  const path = ghPath(positionals);
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
  if (args.some((arg) => !arg.startsWith("-") && isSecretPath(arg))) return { kind: "defer" };
  if (args.some((arg) => arg.startsWith("-"))) return { kind: "defer" };
  const path = commandPath(args);
  if (!path) return { kind: "defer" };
  if (path.root === "help") return allow("helm");
  if (path.root === "completion") return args.length === 2 ? allow("helm") : { kind: "defer" };
  if (path.root === "verify") {
    return args.length >= 2 ? allow("helm") : { kind: "defer" };
  }
  if (path.value === "show:chart" || path.value === "inspect:chart") {
    return args.length === 3 ? allow("helm") : { kind: "defer" };
  }
  return HELM_CREDENTIAL_SAFE_COMMANDS.has(path.value) ? allow("helm") : { kind: "defer" };
}

function parseStandaloneLiteralCommand(command: string, executable: string):
  | { kind: "command"; command: SimpleCommand }
  | { kind: "other" }
  | { kind: "unsafe" } {
  if (!isBashParserInitialized() || !command.trim()) return { kind: "unsafe" };
  if (SHELL_SYNTAX.test(command)) return { kind: "unsafe" };
  const commands = parseBash(command);
  if (commands.length !== 1) return { kind: "unsafe" };
  if (commands[0].name !== executable) return { kind: "other" };
  if (command.trimStart().split(/\s+/, 1)[0] !== executable) return { kind: "unsafe" };
  return { kind: "command", command: commands[0] };
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
const HELM_GLOBAL_FLAGS_WITH_VALUE = new Set<string>();

interface AllowedFlag {
  readonly long?: string;
  readonly short?: string;
  readonly takesValue: boolean;
}

const GH_ALLOWED_FLAGS: readonly AllowedFlag[] = [
  { long: "--repo", short: "-R", takesValue: true },
];

const STRICT_ALLOWED_FLAGS: Readonly<Record<string, readonly AllowedFlag[]>> = {
  kubectl: [
    { long: "--namespace", short: "-n", takesValue: true },
    { long: "--context", takesValue: true },
  ],
  oc: [
    { long: "--namespace", short: "-n", takesValue: true },
    { long: "--context", takesValue: true },
  ],
  npm: [{ long: "--json", takesValue: false }],
};

/** Strip only explicitly audited flags, preserving positional order. */
function parseAllowedFlags(args: readonly string[], specs: readonly AllowedFlag[]): string[] | undefined {
  const positionals: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") return undefined;
    if (!arg.startsWith("-") || arg === "-") {
      positionals.push(arg);
      continue;
    }

    const exact = specs.find((spec) => arg === spec.long || arg === spec.short);
    if (exact) {
      if (!exact.takesValue) continue;
      const value = args[++index];
      if (!value || value.startsWith("-")) return undefined;
      continue;
    }

    const long = specs.find((spec) => spec.takesValue && spec.long && arg.startsWith(`${spec.long}=`));
    if (long) {
      if (arg.slice(arg.indexOf("=") + 1).length === 0) return undefined;
      continue;
    }

    const short = specs.find((spec) => spec.takesValue && spec.short && arg.startsWith(spec.short) && arg.length > spec.short.length);
    if (short) {
      const value = arg.slice(short.short!.length).replace(/^=/, "");
      if (!value || value.startsWith("-")) return undefined;
      continue;
    }

    return undefined;
  }
  return positionals;
}

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

function allow(tool: string): ReadOnlyCliDecision {
  return { kind: "allow", reason: `${tool} auto-allowed by the read-only profile` };
}
