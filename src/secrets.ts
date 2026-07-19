// Secret-file detection and bash secret-read scanning.

import {
  READING_COMMANDS,
  SECRET_EXCEPTIONS,
  SECRET_PATTERNS,
} from "./patterns.js";
import {
  basename,
  matchesAnyGlob,
  parseBash,
} from "./shell.js";

/** True iff `name` is treated as a secret file by policy. */
export function isSecretFileName(name: string): boolean {
  if (!name) return false;
  if (matchesAnyGlob(name, SECRET_EXCEPTIONS)) return false;
  return matchesAnyGlob(name, SECRET_PATTERNS);
}

/** Convenience: run `isSecretFileName` on the basename of `path`. */
export function isSecretPath(path: string): boolean {
  return isSecretFileName(basename(path));
}

/**
 * Scan a bash command using tree-sitter parsing to detect reads of
 * secret files via known viewers or shell input redirection.
 *
 * Returns a human-readable reason string, or null if no secret read is
 * detected.
 *
 * Known limitations (deliberately not covered here):
 *   - creative readers: python -c, awk, ruby -e, sed, tr
 *   - here-docs, process substitution, base64 decode pipelines
 *   - dynamic paths from command substitutions
 * Those are covered by the prompt-level rule injected at SessionStart.
 */
export function parseBashForSecretRead(command: string): string | null {
  if (!command) return null;

  const commands = parseBash(command);

  for (const cmd of commands) {
    // Case 1: input redirect (`< secretfile`) — check redirect targets.
    for (const r of cmd.redirects) {
      if (r.kind === "input" && isSecretPath(r.target)) {
        return `bash redirect from '${basename(r.target)}'`;
      }
    }

    // Case 2: reading command (cat, head, tail, ...) with a secret file as
    // a positional argument.
    if (!READING_COMMANDS.has(cmd.name)) continue;

    for (const arg of cmd.args) {
      if (arg.startsWith("-")) continue;
      if (isSecretPath(arg)) {
        return `bash \`${cmd.name}\` on '${basename(arg)}'`;
      }
    }
  }

  return null;
}
