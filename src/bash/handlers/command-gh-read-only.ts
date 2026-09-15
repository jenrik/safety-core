import type { PolicyObserver } from "../dispatch.js";
import { GH_ALLOWED_FLAGS, GH_CREDENTIAL_SAFE_COMMANDS, GH_GLOBAL_FLAGS_WITH_VALUE, GH_TOP_LEVEL_COMMANDS } from "../policies/read-only.js";
import { allow, commandTokens, defer, hasSecretOperand, parseAllowedFlags, readOnlyHandler } from "./read-only-utils.js";

export const ghReadOnlyHandler: PolicyObserver = readOnlyHandler("gh", "gh-read-only", (args) => {
  if (commandTokens(args, GH_GLOBAL_FLAGS_WITH_VALUE)[0] === "api") return { kind: "ignore" };
  if (hasSecretOperand(args)) return defer("gh-read-only", "gh");
  if (args.length === 1 && ["--help", "--version"].includes(args[0]!)) return allow("gh-read-only", "gh");
  const positionals = parseAllowedFlags(args, GH_ALLOWED_FLAGS);
  if (!positionals) return defer("gh-read-only", "gh");
  const path = ghPath(positionals);
  if (!path || !ghOperandsAreAudited(path.value, path.remaining)) return defer("gh-read-only", "gh");
  return ["help", "completion", "licenses", "status"].includes(path.value) || GH_CREDENTIAL_SAFE_COMMANDS.has(path.value)
    ? allow("gh-read-only", "gh") : defer("gh-read-only", "gh");
});

function ghPath(positionals: readonly string[]): { readonly value: string; readonly remaining: readonly string[] } | undefined {
  const tokens = commandTokens(positionals, GH_GLOBAL_FLAGS_WITH_VALUE);
  const root = tokens[0];
  if (!root || !GH_TOP_LEVEL_COMMANDS.has(root)) return undefined;
  if (["browse", "completion", "help", "licenses", "status", "version"].includes(root)) return { value: root, remaining: tokens.slice(1) };
  const second = tokens[1];
  return second ? { value: `${root}:${second}`, remaining: tokens.slice(2) } : undefined;
}

/** Only paths with reviewed positional grammars may carry extra operands. */
function ghOperandsAreAudited(path: string, remaining: readonly string[]): boolean {
  if (remaining.length === 0) return true;
  return new Set([
    "help", "completion", "extension:search", "ext:search", "extensions:search",
    "project:field-list", "project:item-list", "project:view", "search:commits", "search:issues",
    "search:prs", "search:repos", "workflow:view",
  ]).has(path);
}
