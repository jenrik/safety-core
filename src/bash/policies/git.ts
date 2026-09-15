import { readOnlyAllow, readOnlyDefer, type ReadOnlyInvocationDecision } from "./read-only.js";
import type { BashInitialEnvironment } from "../../authorization.js";

const GIT_EXECUTION_ENVIRONMENT = [
  "GIT_CONFIG_COUNT",
  "GIT_CONFIG_GLOBAL",
  "GIT_CONFIG_PARAMETERS",
  "GIT_CONFIG_SYSTEM",
  "GIT_EXTERNAL_DIFF",
  "GIT_PAGER",
] as const;

const GIT_READ_ONLY_SUBCOMMANDS = new Set([
  "describe",
  "diff",
  "diff-files",
  "diff-index",
  "diff-tree",
  "for-each-ref",
  "log",
  "ls-files",
  "ls-tree",
  "merge-base",
  "name-rev",
  "rev-list",
  "rev-parse",
  "show",
  "show-ref",
  "verify-commit",
  "verify-tag",
]);

/**
 * Git content trust boundary: checked-in and staged content is safe to inspect.
 * Secret files are expected to be excluded by `.gitignore`; the commands below
 * may read tracked working-tree files, the index, and Git objects.
 * `log`, `show`, `verify-commit`, and `verify-tag`, including their configured
 * signature-verification behavior, are accepted inspection paths.
 *
 * Intentionally deferred Git forms:
 *
 * - Index, ref, working-tree, and repository mutations (`add`, `commit`,
 *   `merge`, `rebase`, `reset`, `restore`, `switch`, `tag <name>`, etc.).
 * - State-observing commands that may refresh the index (`status`).
 * - Configuration and remote operations (`config`, `remote`, `fetch`,
 *   `pull`, `push`, and `ls-remote`), which can expose credentials or use the
 *   network.
 * - Working-tree content search (`grep`), which can disclose uncommitted
 *   secret values.
 * - Aliases, global options, and nested subcommands not enumerated below:
 *   their behavior is configuration-dependent or not yet reviewed.
 * - Explicit environment configuration that changes Git's execution route,
 *   including external diff helpers, pagers, and injected Git configuration.
 *
 * They are deferred, rather than denied, so the harness can request the
 * user's native permission for a legitimate use.
 */

// These options either write a file, inspect arbitrary filesystem content, or
// explicitly invoke an external program. The normal configured diff pipeline
// remains part of the accepted Git trust boundary.
const UNSAFE_GIT_OPTIONS = new Set([
  "--ext-diff",
  "--no-index",
  "--open-files-in-pager",
  "--output",
  "--textconv",
]);

/**
 * Proves the narrow Git forms accepted by the generic read-only Bash profile.
 * Git aliases, global configuration options, working-tree queries, and every
 * unreviewed subcommand remain deferred to the harness permission prompt.
 */
export function analyzeGitReadOnlyInvocation(args: readonly string[]): ReadOnlyInvocationDecision {
  if (args.length === 1 && ["--help", "--version", "version"].includes(args[0]!)) {
    return readOnlyAllow("generic-read-only", "git");
  }
  if (hasUnsafeGitOption(args)) return readOnlyDefer("generic-read-only", "git");

  const [subcommand, ...remaining] = args;
  if (!subcommand) return readOnlyDefer("generic-read-only", "git");
  if (GIT_READ_ONLY_SUBCOMMANDS.has(subcommand)) return readOnlyAllow("generic-read-only", "git");

  if (subcommand === "branch" && isBranchListing(remaining)) return readOnlyAllow("generic-read-only", "git");
  if (subcommand === "tag" && isTagListing(remaining)) return readOnlyAllow("generic-read-only", "git");
  if (subcommand === "worktree" && isExactSubcommand(remaining, "list")) return readOnlyAllow("generic-read-only", "git");
  if (subcommand === "submodule" && isExactSubcommand(remaining, "status")) return readOnlyAllow("generic-read-only", "git");
  if (subcommand === "reflog" && isExactSubcommand(remaining, "show")) return readOnlyAllow("generic-read-only", "git");

  return readOnlyDefer("generic-read-only", "git");
}

/**
 * Supplies only execution-route variables from a harness environment. This
 * keeps process secrets out of Bash analysis while proving these variables are
 * absent when the shared read-only guard evaluates Git. The ambient `PAGER`
 * is part of the harness's normal Git output route; an explicit `PAGER`
 * export in analyzed Bash is still deferred by the shared guard.
 */
export function gitPolicyInitialEnvironment(environment: Readonly<Record<string, string | undefined>>): BashInitialEnvironment {
  const values = Object.fromEntries(
    Object.entries(environment).filter(([name, value]) => value !== undefined && isGitExecutionEnvironment(name)),
  );
  return Object.freeze({ kind: "verified", values: Object.freeze(values) });
}

export function hasUnsafeGitOption(args: readonly string[]): boolean {
  return args.some((argument) => {
    if (!argument.startsWith("--") || argument === "--") return false;
    const option = argument.split("=", 1)[0]!;
    // Git accepts unambiguous long-option prefixes, so inspect prefixes rather
    // than only the canonical spelling of an unsafe option.
    return [...UNSAFE_GIT_OPTIONS].some((unsafeOption) => unsafeOption.startsWith(option));
  });
}

function isBranchListing(args: readonly string[]): boolean {
  return args.length === 0 || (args.length === 1 && ["--list", "-l", "--show-current"].includes(args[0]!));
}

function isTagListing(args: readonly string[]): boolean {
  return args.length === 0 || (args.length === 1 && ["--list", "-l"].includes(args[0]!));
}

function isExactSubcommand(args: readonly string[], subcommand: string): boolean {
  return args.length === 1 && args[0] === subcommand;
}

function isGitExecutionEnvironment(name: string): boolean {
  return GIT_EXECUTION_ENVIRONMENT.includes(name as typeof GIT_EXECUTION_ENVIRONMENT[number])
    || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name);
}
