// gh-api-specific policy: auto-allow verifiably read-only `gh api` calls,
// deny mutating ones, defer everything else to the harness' default gate.
//
// "Read-only" for `gh api` is verb-dependent, not prefix-dependent (unlike
// e.g. `cat`/`tail`), so this can't be expressed as a static allow-list glob.
//
// Per `gh api --help`: the default method is GET, and switches to POST if
// any parameters (-f/--raw-field, -F/--field) or a body (--input) are added
// -- UNLESS an explicit -X/--method overrides it (e.g. `-X GET -f q=...` is
// still a GET). So an explicit --method is authoritative; only in its
// absence does parameter/body presence decide the implied method.

import { parseBash, type SimpleCommand } from "./shell.js";

export type GhApiDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" }; // not a `gh api` command at all

const METHOD_FLAGS_WITH_VALUE = new Set(["-X", "--method"]);
const PARAM_FLAGS = new Set(["-f", "--raw-field", "-F", "--field"]);
const BODY_FLAGS = new Set(["--input"]);

/**
 * Analyse a shell command for `gh api` policy. Returns:
 *   - allow  → hook should override permission gate to allow
 *   - deny   → hook should override permission gate to deny
 *   - defer  → hook should stay silent; let harness default rules decide
 *   - ignore → command is not `gh api`
 */
export function analyzeGhApiCommand(command: string): GhApiDecision {
  const commands = parseBash(command);
  const gh = commands.find(isGhApi);
  if (!gh) return { kind: "ignore" };

  const endpoint = gh.args[1]; // args[0] is "api"
  if (endpoint && /^\/?graphql\/?$/.test(endpoint)) {
    // A GraphQL request is a POST by protocol even for reads -- verb-only
    // logic can't distinguish a query from a mutation. Let the harness's
    // default/judge decide instead of guessing.
    return { kind: "defer" };
  }

  const explicitMethod = findFlagValue(gh.args, METHOD_FLAGS_WITH_VALUE);
  if (explicitMethod !== undefined) {
    const method = explicitMethod.toUpperCase();
    if (method === "GET" || method === "HEAD") {
      return { kind: "allow", reason: `gh api --method ${method} auto-allowed (read-only)` };
    }
    return { kind: "deny", reason: `gh api --method ${method} is not read-only` };
  }

  const hasParamsOrBody = gh.args.some(
    (a) => PARAM_FLAGS.has(a) || BODY_FLAGS.has(a) || hasLongFlagPrefix(a, PARAM_FLAGS) || hasLongFlagPrefix(a, BODY_FLAGS),
  );
  if (hasParamsOrBody) {
    return {
      kind: "deny",
      reason: "gh api with -f/-F/--input and no explicit --method defaults to POST, not read-only",
    };
  }

  return { kind: "allow", reason: "gh api auto-allowed (GET, no parameters)" };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function isGhApi(cmd: SimpleCommand): boolean {
  return cmd.name === "gh" && cmd.args[0] === "api";
}

/** Return the value of a `-X value` / `--method value` / `--method=value` flag, or undefined. */
function findFlagValue(args: readonly string[], flags: ReadonlySet<string>): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (flags.has(arg)) return args[i + 1];
    const eq = arg.indexOf("=");
    if (eq !== -1 && flags.has(arg.slice(0, eq))) return arg.slice(eq + 1);
  }
  return undefined;
}

/** True if `arg` is `--flag=value` for one of the given long flags. */
function hasLongFlagPrefix(arg: string, flags: ReadonlySet<string>): boolean {
  const eq = arg.indexOf("=");
  if (eq === -1) return false;
  return flags.has(arg.slice(0, eq));
}
