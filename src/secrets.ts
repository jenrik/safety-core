// Secret-file detection and bash secret-read scanning.

import {
  READING_COMMANDS,
  SECRET_EXCEPTIONS,
  SECRET_PATTERNS,
} from "./patterns.js";
import {
  basename,
  matchesAnyGlob,
  skipEnvAssignments,
  splitShellSegments,
  stripQuotes,
  tokenize,
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

// Best-effort scan: return a human-readable reason string if `command` reads a
// secret file via a known viewer or shell input redirection, else null.
//
// Known limitations (deliberately not covered here):
//   - creative readers: python -c, awk, ruby -e, sed, tr
//   - here-docs, process substitution, base64 decode pipelines
//   - dynamic paths from command substitutions
// Those are covered by the prompt-level rule injected at SessionStart.
export function parseBashForSecretRead(command: string): string | null {
  if (!command) return null;

  for (const segment of splitShellSegments(command)) {
    // Case 1: `< secretfile` redirection.
    const redirect = segment.match(/<\s*([^\s<>|;&'"]+)/);
    if (redirect) {
      const target = stripQuotes(redirect[1]);
      if (isSecretPath(target)) {
        return `bash redirect from '${basename(target)}'`;
      }
    }

    // Case 2: reading command with a secret file as a positional argument.
    const tokens = tokenize(segment).map(stripQuotes);
    if (tokens.length === 0) continue;

    const cmdIdx = skipEnvAssignments(tokens);
    if (cmdIdx >= tokens.length) continue;

    const cmd = basename(tokens[cmdIdx]);
    if (!READING_COMMANDS.has(cmd)) continue;

    for (const arg of tokens.slice(cmdIdx + 1)) {
      if (arg.startsWith("-")) continue;
      if (isSecretPath(arg)) {
        return `bash \`${cmd}\` on '${basename(arg)}'`;
      }
    }
  }

  return null;
}
