// Secret-file detection and bash secret-read scanning.

import {
  SECRET_EXCEPTIONS,
  SECRET_PATTERNS,
} from "./patterns.js";
import {
  basename,
  matchesAnyGlob,
} from "./shell.js";
import { analyzeBashAuthorization } from "./authorization.js";

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
  const policy = analyzeBashAuthorization({ source: command }).policies
    .find((evidence) => evidence.name === "secret-read" && evidence.decision === "deny");
  return policy?.reason ?? null;
}
