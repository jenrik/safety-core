// Parsed read-only command profiles for CLI tools whose native permission
// patterns cannot safely distinguish subcommands from shell syntax.

import { isBashParserInitialized, parseBash, type SimpleCommand } from "./shell.js";

export type ReadOnlyCliDecision =
  | { kind: "allow"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

const SHELL_SYNTAX = /[;&|<>`$(){}'"\\*?\[\]~]/;
const GH_BROWSER_FLAGS = new Set(["--web", "-w"]);
const GH_OUTPUT_FLAGS = new Set(["--output", "-o", "--clobber"]);
const GH_SHOW_TOKEN_FLAGS = new Set(["--show-token", "-t"]);
const HELM_UNSAFE_FLAGS = new Set(["--dependency-update", "--output-dir", "--post-renderer", "--post-renderer-args"]);

const GH_TOP_LEVEL_COMMANDS = new Set([
  "alias", "agent", "agent-task", "agent-tasks", "agents", "attestation", "at",
  "auth", "browse", "cache", "codespace", "completion", "cs", "discussion",
  "extension", "ext", "extensions", "gist", "gpg-key", "help", "issue", "label",
  "licenses", "org", "pr", "project", "release", "repo", "ruleset", "rs", "run",
  "search", "secret", "skill", "skills", "ssh-key", "status", "variable", "version",
  "workflow",
]);

const GH_READ_ONLY_COMMANDS = new Set([
  "alias:list", "alias:ls",
  "agent:list", "agent:view", "agent-task:list", "agent-task:view", "agent-tasks:list", "agent-tasks:view", "agents:list", "agents:view",
  "attestation:trusted-root", "attestation:verify", "at:trusted-root", "at:verify",
  "cache:list", "cache:ls",
  "codespace:list", "codespace:logs", "codespace:ports", "codespace:view", "codespace:ls", "cs:list", "cs:logs", "cs:ports", "cs:view", "cs:ls",
  "discussion:list", "discussion:view", "discussion:ls",
  "extension:list", "extension:ls", "extension:search", "ext:list", "ext:ls", "ext:search", "extensions:list", "extensions:ls", "extensions:search",
  "gist:list", "gist:view", "gist:ls", "gpg-key:list", "gpg-key:ls",
  "issue:list", "issue:status", "issue:view", "issue:ls", "label:list", "label:ls", "org:list",
  "pr:checks", "pr:diff", "pr:list", "pr:status", "pr:view",
  "project:field-list", "project:item-list", "project:list", "project:view", "project:ls",
  "release:list", "release:ls", "release:verify", "release:verify-asset", "release:view",
  "repo:autolink:list", "repo:autolink:view", "repo:autolink:ls", "repo:deploy-key:list", "repo:deploy-key:ls",
  "repo:gitignore:list", "repo:gitignore:view", "repo:gitignore:ls", "repo:license:list", "repo:license:view", "repo:license:ls",
  "repo:list", "repo:ls", "repo:read-dir", "repo:read-file", "repo:view",
  "ruleset:check", "ruleset:list", "ruleset:view", "ruleset:ls", "rs:check", "rs:list", "rs:view", "rs:ls",
  "run:list", "run:view", "run:watch", "run:ls",
  "search:code", "search:commits", "search:issues", "search:prs", "search:repos",
  "secret:list", "secret:ls", "skill:list", "skill:ls", "skill:preview", "skill:search", "skill:show",
  "skills:list", "skills:ls", "skills:preview", "skills:search", "skills:show",
  "ssh-key:list", "ssh-key:ls", "variable:list", "variable:ls", "workflow:list", "workflow:view", "workflow:ls",
]);

const GH_EXACT_MODES = new Map<string, readonly string[]>([
  ["browse", ["--no-browser"]],
  ["issue:develop", ["--list"]],
  ["repo:set-default", ["--view"]],
  ["codespace:ssh", ["--config"]],
  ["cs:ssh", ["--config"]],
  ["extension:upgrade", ["--dry-run"]],
  ["ext:upgrade", ["--dry-run"]],
  ["extensions:upgrade", ["--dry-run"]],
  ["skill:update", ["--dry-run"]],
  ["skills:update", ["--dry-run"]],
]);

const HELM_READ_ONLY_COMMANDS = new Set([
  "completion", "dependency:list", "env", "get:all", "get:hooks", "get:manifest",
  "get:metadata", "get:notes", "get:values", "history", "lint", "list", "plugin:list",
  "repo:list", "search:hub", "search:repo", "show:all", "show:chart", "show:crds",
  "show:readme", "show:values", "status", "template", "verify", "version",
]);
const HELM_READ_ONLY_ROOT_COMMANDS = new Set([
  "env", "history", "lint", "list", "status", "template", "verify", "version",
]);

/** Auto-allow only documented `gh` reads; all other forms retain native prompts. */
export function analyzeGhReadOnlyCommand(command: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, "gh");
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (hasGhUnsafeFlag(args)) return { kind: "defer" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version")) return allow("gh");
  if (firstGhSubcommand(args) === "api") return { kind: "ignore" };

  const path = ghPath(args);
  if (!path) return { kind: "defer" };
  if (path.value === "help" || path.value === "completion" || path.value === "licenses" || path.value === "status") return allow("gh");
  if (path.value === "auth:status") return hasGhTokenFlag(args) ? { kind: "defer" } : allow("gh");

  const exactArgs = GH_EXACT_MODES.get(path.value);
  if (exactArgs) return sameArguments(args, [...path.value.split(":"), ...exactArgs]) ? allow("gh") : { kind: "defer" };

  if ((path.value === "codespace:ports" || path.value === "cs:ports") &&
    path.remaining.some((arg) => arg === "forward" || arg === "visibility")) return { kind: "defer" };

  return GH_READ_ONLY_COMMANDS.has(path.value) ? allow("gh") : { kind: "defer" };
}

/** Auto-allow Helm inspection, rendering, and validation commands only. */
export function analyzeHelmReadOnlyCommand(command: string): ReadOnlyCliDecision {
  const parsed = parseStandaloneLiteralCommand(command, "helm");
  if (parsed.kind !== "command") return parsed.kind === "other" ? { kind: "ignore" } : { kind: "defer" };

  const { args } = parsed.command;
  if (args.some((arg) => isFlag(arg, HELM_UNSAFE_FLAGS))) return { kind: "defer" };
  if (args.length === 1 && (args[0] === "--help" || args[0] === "--version")) return allow("helm");
  const path = commandPath(args);
  if (!path) return { kind: "defer" };
  return (path.value === "help" || path.value.startsWith("help:") || path.value === "completion" ||
    path.value.startsWith("completion:") || HELM_READ_ONLY_ROOT_COMMANDS.has(path.root) ||
    HELM_READ_ONLY_COMMANDS.has(path.value)) ? allow("helm") : { kind: "defer" };
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

function hasGhUnsafeFlag(args: readonly string[]): boolean {
  return args.some((arg) => isFlag(arg, GH_BROWSER_FLAGS) || isFlag(arg, GH_OUTPUT_FLAGS));
}

function hasGhTokenFlag(args: readonly string[]): boolean {
  return args.some((arg) => isFlag(arg, GH_SHOW_TOKEN_FLAGS));
}

function isFlag(arg: string, flags: ReadonlySet<string>): boolean {
  if (flags.has(arg) || [...flags].some((flag) => arg.startsWith(`${flag}=`))) return true;
  return arg.startsWith("-") && !arg.startsWith("--") && arg.slice(1).split("").some((letter) => flags.has(`-${letter}`));
}

function allow(tool: string): ReadOnlyCliDecision {
  return { kind: "allow", reason: `${tool} auto-allowed by the read-only profile` };
}
