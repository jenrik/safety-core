// Secret-file detection and bash secret-read scanning.
// TODO: Revisit secret-read detection around the Bash CST walker and remove
// this repeated whole-command compatibility evaluation in favor of its
// structured secret-read evidence.

import {
  SECRET_EXCEPTIONS,
  SECRET_PATTERNS,
} from "./patterns.js";
import {
  basename,
  matchesAnyGlob,
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
