// Scope, decided by a human: enforce native `gh` subcommands that create pull
// requests, including `gh pr` aliases. Direct `gh api` calls are denied and
// steered to native subcommands so pre-existing multiword aliases cannot hide
// a pull-request write. Literal shell wrappers are inspected only to keep
// those `gh` forms from bypassing policy.
//
// Out of scope, also by human decision: arbitrary HTTP clients, executable or
// PATH shadowing, and dynamically generated scripts. Those require a broader
// execution model (potentially symbolic execution) rather than command policy.
// Direct HTTP is instead steered to `gh` by the existing GitHub safety policy.
//
// This is intentionally separate from the read-only gh-api profile: PR
// creation is a bounded write capability.

import { loadProfileConfig, type GhPrCreateProfileConfig } from "./config.js";
import { basename, isBashParserInitialized, parseBash, stripQuotes, type SimpleCommand } from "./shell.js";

export interface GhPrCreatePolicy {
  enabled: boolean;
  allowedRepositories: readonly string[];
  allowedOrganizations: readonly string[];
}

export type GhPrCreateDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "ignore" };

interface RepositoryIdentifier {
  host: string;
  owner: string;
  name: string;
}

interface OrganizationIdentifier {
  host: string;
  owner: string;
}

interface PullRequestAttempt {
  source: "gh pr create" | "gh api" | "gh alias" | "gh extension";
  repository?: string;
}

interface GhInvocation {
  args: string[];
}

const REPO_FLAGS = new Set(["-R", "--repo"]);
const GH_GLOBAL_FLAGS_WITH_VALUE = new Set(["-R", "--repo", "--hostname"]);
const GH_PR_FLAGS_WITH_VALUE = new Set([
  "-R",
  "--repo",
  "-a",
  "--assignee",
  "-B",
  "--base",
  "-b",
  "--body",
  "-F",
  "--body-file",
  "-H",
  "--head",
  "-l",
  "--label",
  "-m",
  "--milestone",
  "-p",
  "--project",
  "--recover",
  "-r",
  "--reviewer",
  "-t",
  "--title",
  "-T",
  "--template",
]);
const GH_API_WRITE_INPUT_FLAGS = new Set(["-f", "--raw-field", "-F", "--field", "--input"]);
const GH_WRAPPERS = new Set([
  "command",
  "doas",
  "env",
  "exec",
  "ionice",
  "nice",
  "nohup",
  "setsid",
  "stdbuf",
  "sudo",
  "time",
  "timeout",
]);
const SHELL_INTERPRETERS = new Set(["bash", "dash", "fish", "ksh", "sh", "zsh"]);
const KNOWN_GH_TOP_LEVEL_COMMANDS = new Set([
  "alias",
  "api",
  "attestation",
  "agent",
  "agent-task",
  "agent-tasks",
  "agents",
  "at",
  "auth",
  "browse",
  "cache",
  "codespace",
  "completion",
  "config",
  "extension",
  "ext",
  "extensions",
  "copilot",
  "discussion",
  "environment",
  "exit-codes",
  "gist",
  "gpg-key",
  "help",
  "issue",
  "label",
  "licenses",
  "org",
  "pr",
  "project",
  "preview",
  "release",
  "repo",
  "rs",
  "ruleset",
  "run",
  "search",
  "secret",
  "skill",
  "skills",
  "ssh-key",
  "status",
  "variable",
  "version",
  "workflow",
]);

/**
 * Read the structured profile from the shared runtime configuration. Invalid
 * values are discarded so a malformed config cannot broaden permission.
 */
export function loadGhPrCreatePolicy(path?: string): GhPrCreatePolicy {
  const profile = loadProfileConfig(path).ghPrCreate;
  return {
    enabled: isRecord(profile) && profile.enabled === true,
    allowedRepositories: stringArray(profile?.allowedRepositories),
    allowedOrganizations: stringArray(profile?.allowedOrganizations),
  };
}

/**
 * Analyse every pull-request creation attempt in a shell command. Native
 * `gh pr create` is allowed only for explicitly scoped targets. Direct API
 * creation is denied even for an allowlisted target, steering the agent to
 * the auditable native command; REST and GraphQL variants cannot bypass the
 * repository/organization boundary.
 */
export function analyzeGhPrCreateCommand(
  command: string,
  policy: GhPrCreatePolicy = loadGhPrCreatePolicy(),
): GhPrCreateDecision {
  if (!policy.enabled) return { kind: "ignore" };

  if (!isBashParserInitialized()) {
    return {
      kind: "deny",
      reason: "Bash blocked: the ghPrCreate safety parser is unavailable. This indicates a damaged safety-core hook deployment; fix and redeploy the packaged hook before retrying.",
    };
  }

  if (/\\\r?\n/.test(command) && hasPossiblePullRequestCreation(command)) {
    return {
      kind: "deny",
      reason: "Pull-request creation is blocked through a shell line continuation; invoke native gh pr create as a standalone one-line command instead",
    };
  }

  const parsedCommands = parseBash(command);
  if (hasShellIndirection(command, parsedCommands)) {
    return {
      kind: "deny",
      reason: "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead",
    };
  }

  const commands = expandShellCommands(parsedCommands);
  if (commands.some(isPotentialDynamicGhInvocation)) {
    return {
      kind: "deny",
      reason: "Dynamic shell command blocked: it could invoke gh outside the ghPrCreate policy; use native gh pr create instead",
    };
  }
  if (commands.some(isUnknownGhInvocation)) {
    return {
      kind: "deny",
      reason: "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead",
    };
  }

  const attempts = commands.flatMap(pullRequestAttempts);
  if (attempts.length === 0) return { kind: "ignore" };

  for (const attempt of attempts) {
    if (attempt.source === "gh alias") {
      return {
        kind: "deny",
        reason: "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead",
      };
    }

    if (attempt.source === "gh extension") {
      return {
        kind: "deny",
        reason: "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead",
      };
    }

    if (attempt.source === "gh api") {
      return {
        kind: "deny",
        reason: "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead",
      };
    }

    if (!attempt.repository) {
      return {
        kind: "deny",
        reason:
          "Pull-request creation is blocked: provide an explicit --repo HOST/OWNER/REPO target that is allowlisted by the ghPrCreate profile",
      };
    }

    if (!hasExplicitHost(attempt.repository)) {
      return {
        kind: "deny",
        reason: "Pull-request creation is blocked: use an explicit --repo HOST/OWNER/REPO target so the allowlist cannot be redirected by GH_HOST",
      };
    }

    if (!isAllowedRepository(attempt.repository, policy)) {
      return {
        kind: "deny",
        reason: `Pull-request creation is blocked: repository ${attempt.repository} is not allowlisted by the ghPrCreate profile`,
      };
    }
  }

  // A permission override applies to the whole Bash tool call. Only approve a
  // command composed exclusively of recognized native PR creation attempts.
  if (commands.every((simpleCommand) => pullRequestAttempts(simpleCommand).length > 0)) {
    return {
      kind: "allow",
      reason: "gh pr create auto-allowed for an allowlisted repository",
    };
  }

  return {
    kind: "deny",
    reason: "Pull-request creation must be the only command in this Bash invocation; run native gh pr create separately",
  };
}

function pullRequestAttempts(command: SimpleCommand): PullRequestAttempt[] {
  const invocation = unwrapGhCommand(command);
  if (!invocation) return [];
  const subcommand = findGhSubcommand(invocation.args);
  if (!subcommand) return [];

  if (subcommand.name === "pr" && isGhPrCreate(invocation.args.slice(subcommand.index + 1))) {
    const repositories = findRepoFlagValues(invocation.args);
    if (repositories === undefined || repositories.length === 0) {
      return [{ source: "gh pr create" }];
    }
    return repositories.map((repository) => ({ source: "gh pr create", repository }));
  }

  if (subcommand.name === "alias" && isGhAliasDefinition(invocation.args.slice(subcommand.index + 1))) {
    return [{ source: "gh alias" }];
  }

  if (["extension", "ext", "extensions"].includes(subcommand.name) && invocation.args[subcommand.index + 1] === "exec") {
    return [{ source: "gh extension" }];
  }

  return subcommand.name === "api" ? [{ source: "gh api" }] : [];
}

/** Extract `gh` arguments through common transparent command wrappers. */
function unwrapGhCommand(command: SimpleCommand): GhInvocation | undefined {
  if (command.name === "gh") return { args: command.args };
  if (!GH_WRAPPERS.has(command.name)) return undefined;

  const ghIndex = command.args.findIndex((arg) => basename(canonicalShellWord(arg)) === "gh");
  return ghIndex === -1 ? undefined : { args: command.args.slice(ghIndex + 1) };
}

/** Return the first non-global `gh` subcommand and its position. */
function findGhSubcommand(args: readonly string[]): { name: string; index: number } | undefined {
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (GH_GLOBAL_FLAGS_WITH_VALUE.has(arg)) {
      index++;
      continue;
    }
    if (hasAttachedFlagValue(arg, GH_GLOBAL_FLAGS_WITH_VALUE)) continue;
    if (arg.startsWith("-")) continue;
    return { name: arg, index };
  }
  return undefined;
}

function isGhPrCreate(argsAfterPr: readonly string[]): boolean {
  for (let index = 0; index < argsAfterPr.length; index++) {
    const arg = argsAfterPr[index];
    if (arg === "create" || arg === "new") return true;
    if (GH_PR_FLAGS_WITH_VALUE.has(arg)) {
      index++;
      continue;
    }
    if (hasAttachedFlagValue(arg, GH_PR_FLAGS_WITH_VALUE) || arg.startsWith("-")) continue;
    return false;
  }
  return false;
}

function isGhAliasDefinition(argsAfterAlias: readonly string[]): boolean {
  // gh aliases expand before command dispatch, including multiword aliases
  // such as `api create-pr`; permit none to avoid a hidden gh subcommand.
  return argsAfterAlias[0] === "set" || argsAfterAlias[0] === "import";
}

function isUnknownGhInvocation(command: SimpleCommand): boolean {
  const invocation = unwrapGhCommand(command);
  const subcommand = invocation && findGhSubcommand(invocation.args);
  return subcommand !== undefined && !KNOWN_GH_TOP_LEVEL_COMMANDS.has(subcommand.name);
}

function isPotentialDynamicGhInvocation(command: SimpleCommand): boolean {
  if (!command.name.includes("$") && !command.name.includes("`")) return false;

  const args = command.args.map(canonicalShellWord);
  const prIndex = args.indexOf("pr");
  if (prIndex !== -1 && (args[prIndex + 1] === "create" || args[prIndex + 1] === "new")) return true;

  const apiIndex = args.indexOf("api");
  return apiIndex !== -1 && inferredGhApiMethod(args.slice(apiIndex + 1)) === "POST";
}

/** Return every --repo/-R value; undefined represents a malformed flag. */
function findRepoFlagValues(args: readonly string[]): string[] | undefined {
  const repositories: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (REPO_FLAGS.has(arg)) {
      const value = args[++i];
      if (!value || value.startsWith("-")) return undefined;
      repositories.push(value);
      continue;
    }
    if (arg.startsWith("--repo=")) {
      const value = arg.slice("--repo=".length);
      if (!value) return undefined;
      repositories.push(value);
      continue;
    }
    if (arg.startsWith("-R=")) {
      const value = arg.slice("-R=".length);
      if (!value) return undefined;
      repositories.push(value);
      continue;
    }
    if (arg.startsWith("-R") && arg.length > 2) {
      repositories.push(arg.slice(2));
    }
  }

  return repositories;
}

function inferredGhApiMethod(args: readonly string[]): string {
  const explicitMethod = findGhApiMethod(args);
  if (explicitMethod) return explicitMethod.toUpperCase();
  return hasGhApiWriteInput(args) ? "POST" : "GET";
}

function findGhApiMethod(args: readonly string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "-X" || arg === "--method") return args[i + 1];
    if (arg.startsWith("--method=")) return arg.slice("--method=".length);
    if (arg.startsWith("-X=")) return arg.slice("-X=".length);
    if (arg.startsWith("-X") && arg.length > 2) return arg.slice(2);
  }
  return undefined;
}

function hasGhApiWriteInput(args: readonly string[]): boolean {
  return args.some(
    (arg) =>
      GH_API_WRITE_INPUT_FLAGS.has(arg) ||
      hasAttachedFlagValue(arg, GH_API_WRITE_INPUT_FLAGS) ||
      ((arg.startsWith("-f") || arg.startsWith("-F")) && arg.length > 2),
  );
}

function hasAttachedFlagValue(arg: string, flags: ReadonlySet<string>): boolean {
  const equals = arg.indexOf("=");
  return equals !== -1 && flags.has(arg.slice(0, equals));
}

function hasPossiblePullRequestCreation(command: string): boolean {
  const normalized = stripQuotes(command);
  return /\bgh\s+pr\s+(?:create|new)\b/i.test(normalized)
    || /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s+pr\s+(?:create|new)\b/i.test(normalized)
    || /\bgh\s+api\b/i.test(normalized);
}

/** Block literal commands piped to a shell before a quoted script can hide them. */
function hasShellIndirection(command: string, parsedCommands: readonly SimpleCommand[]): boolean {
  if (!hasPossiblePullRequestCreation(command)) return false;
  if (parsedCommands.some((simpleCommand) => {
    const script = shellScript(simpleCommand);
    return script !== undefined && hasPossiblePullRequestCreation(script);
  })) {
    return true;
  }

  const normalized = stripQuotes(command);
  return /\|\s*(?:env\s+)?(?:bash|dash|fish|ksh|sh|zsh|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)(?:\s|$)/i.test(normalized);
}

function canonicalShellWord(word: string): string {
  return stripQuotes(word);
}

/** Expand literal `sh -c` and `eval` payloads so they cannot hide gh calls. */
function expandShellCommands(commands: readonly SimpleCommand[], depth = 0): SimpleCommand[] {
  if (depth >= 4) return [...commands];

  const expanded: SimpleCommand[] = [];
  for (const command of commands) {
    expanded.push(command);
    const script = shellScript(command);
    if (script) expanded.push(...expandShellCommands(parseBash(script), depth + 1));
  }
  return expanded;
}

function shellScript(command: SimpleCommand): string | undefined {
  if (command.name === "eval") return command.args.join(" ") || undefined;
  if (!SHELL_INTERPRETERS.has(command.name)) return undefined;

  const commandFlag = command.args.findIndex((arg) => arg === "-c" || arg === "--command");
  return commandFlag === -1 ? undefined : command.args[commandFlag + 1];
}

function isAllowedRepository(repository: string, policy: GhPrCreatePolicy): boolean {
  const target = normalizeRepository(repository);
  if (!target) return false;

  return policy.allowedRepositories.some((candidate) => {
    const allowed = normalizeRepository(candidate);
    return allowed !== undefined && repositoriesEqual(target, allowed);
  }) || policy.allowedOrganizations.some((candidate) => {
    const allowed = normalizeOrganization(candidate);
    return allowed !== undefined && target.host === allowed.host && target.owner === allowed.owner;
  });
}

function hasExplicitHost(repository: string): boolean {
  return repository.trim().split("/").length === 3;
}

/** OWNER/REPO defaults to github.com; HOST/OWNER/REPO selects another host. */
function normalizeRepository(value: string): RepositoryIdentifier | undefined {
  const parts = value.trim().toLowerCase().split("/");
  const [host, owner, name] = parts.length === 2
    ? ["github.com", parts[0], parts[1]]
    : parts.length === 3
      ? [parts[0], parts[1], parts[2]]
      : [];
  return isIdentifier(host) && isIdentifier(owner) && isIdentifier(name) ? { host, owner, name } : undefined;
}

/** OWNER defaults to github.com; HOST/OWNER selects another host. */
function normalizeOrganization(value: string): OrganizationIdentifier | undefined {
  const parts = value.trim().toLowerCase().split("/");
  const [host, owner] = parts.length === 1
    ? ["github.com", parts[0]]
    : parts.length === 2
      ? [parts[0], parts[1]]
      : [];
  return isIdentifier(host) && isIdentifier(owner) ? { host, owner } : undefined;
}

function repositoriesEqual(left: RepositoryIdentifier, right: RepositoryIdentifier): boolean {
  return left.host === right.host && left.owner === right.owner && left.name === right.name;
}

function isIdentifier(value: string | undefined): value is string {
  return value !== undefined && /^[a-z0-9][a-z0-9._-]*$/.test(value);
}

function isRecord(value: unknown): value is GhPrCreateProfileConfig {
  return typeof value === "object" && value !== null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
