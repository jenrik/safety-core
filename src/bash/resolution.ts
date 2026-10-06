import { hasBinding, lookupBinding } from "./environment.js";
import type { NormalizedCommand } from "./expand.js";
import { BASH_FUNCTIONS_CAPTURED_FACT } from "./policy-environment.js";
import type { BashShellState } from "./state.js";

/** Who performs the lookup for a child argv, independently of its provenance. */
export type BashLookupDomain = "shell" | "shell-no-functions" | "builtin-only" | "external-path";
export type BashExecutionTargetKind = "builtin" | "shell-function" | "external-path" | "unresolved";

// Bash's builtins (not just the subset for which we model state transitions).
const BASH_BUILTINS = new Set([
  ".",
  ":",
  "[",
  "alias",
  "bg",
  "bind",
  "break",
  "builtin",
  "caller",
  "cd",
  "command",
  "compgen",
  "complete",
  "compopt",
  "continue",
  "declare",
  "dirs",
  "disown",
  "echo",
  "enable",
  "eval",
  "exec",
  "exit",
  "export",
  "false",
  "fc",
  "fg",
  "getopts",
  "hash",
  "help",
  "history",
  "jobs",
  "kill",
  "let",
  "local",
  "logout",
  "mapfile",
  "popd",
  "printf",
  "pushd",
  "pwd",
  "read",
  "readarray",
  "readonly",
  "return",
  "set",
  "shift",
  "shopt",
  "source",
  "suspend",
  "test",
  "times",
  "trap",
  "true",
  "type",
  "typeset",
  "ulimit",
  "umask",
  "unalias",
  "unset",
  "wait",
]);

export function isBashBuiltin(name: string): boolean {
  return BASH_BUILTINS.has(name);
}

export function resolveBashExecutionTarget(
  command: NormalizedCommand,
  state: BashShellState,
  domain: BashLookupDomain,
): BashExecutionTargetKind {
  const executable = command.executable;
  if (!executable || executable.kind !== "known" || !executable.value) return "unresolved";
  const name = executable.value;
  if (domain === "external-path") return pathLookupUncertain(state, name) ? "unresolved" : "external-path";
  if (domain === "builtin-only") return !name.includes("/") && BASH_BUILTINS.has(name) ? "builtin" : "unresolved";
  if (name.includes("/")) return pathLookupUncertain(state, name) ? "unresolved" : "external-path";
  if (domain === "shell") {
    if (state.functionCandidates.has(name)) return state.missingFunctions.has(name) ? "unresolved" : "shell-function";
    const environment = state.environment;
    if (!hasBinding(environment, BASH_FUNCTIONS_CAPTURED_FACT) && environment.missingBindings === "unknown")
      return "unresolved";
    if (
      hasBinding(environment, BASH_FUNCTIONS_CAPTURED_FACT) &&
      lookupBinding(environment, BASH_FUNCTIONS_CAPTURED_FACT).value.kind !== "known"
    )
      return "unresolved";
  }
  const target = BASH_BUILTINS.has(name) ? "builtin" : "external-path";
  if (target === "external-path" && pathLookupUncertain(state, name)) return "unresolved";
  return target;
}

/**
 * A filesystem lookup that depends on the shell's current directory is
 * uncertain after an unmodelled directory change. Builtins and shell functions
 * are unaffected because they are not located through the filesystem. Absolute
 * paths are also unaffected because the kernel resolves them without cwd.
 */
function pathLookupUncertain(state: BashShellState, name: string): boolean {
  return state.cwdUncertain && !name.startsWith("/");
}
