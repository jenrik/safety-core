// Tiny best-effort shell helpers. These do NOT implement full POSIX shell
// semantics — creative constructs (here-docs, process substitution, python -c
// wrappers, awk pipelines) are covered by the prompt-level rule injected at
// session start. The shell scanner is a safety net for the obvious cases.

/** Return the final path component (no trailing slash handling needed). */
export function basename(path: string): string {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "";
}

/** Match a filename against fnmatch-style globs (`*` matches anything). */
export function matchesAnyGlob(name: string, patterns: readonly string[]): boolean {
  const lower = name.toLowerCase();
  return patterns.some((pattern) => {
    const source =
      "^" +
      pattern
        .toLowerCase()
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*") +
      "$";
    return new RegExp(source).test(lower);
  });
}

// Split a shell command on common statement separators (`&&`, `||`, `;`, `|`,
// `&`). Callers still need to strip quotes on individual tokens.
export function splitShellSegments(command: string): string[] {
  return command.split(/&&|\|\||;|\||&/).map((s) => s.trim()).filter(Boolean);
}

// Very rough tokenizer that respects single/double quotes. Sufficient for
// scanning positional arguments; not a substitute for a real parser.
export function tokenize(segment: string): string[] {
  return segment.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
}

export function stripQuotes(token: string): string {
  return token.replace(/^['"]|['"]$/g, "");
}

const ENV_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Skip leading `FOO=bar` env-assignments, returning the index of the command word. */
export function skipEnvAssignments(tokens: string[]): number {
  let i = 0;
  while (i < tokens.length && ENV_ASSIGN.test(tokens[i])) i++;
  return i;
}
