import type { PolicyObserver } from "../dispatch.js";
import { allow, defer, hasSecretOperand, readOnlyHandler } from "./read-only-utils.js";
import { ghCommandGrammarMatches, parseGhCommandLine } from "./gh-command-line.js";

export const ghReadOnlyHandler: PolicyObserver = readOnlyHandler("gh", "gh-read-only", (args) => {
  if (hasSecretOperand(args)) return defer("gh-read-only", "gh");
  const parsed = parseGhCommandLine(args);
  if (parsed.kind === "root-version") return defer("gh-read-only", "gh");
  if (parsed.kind === "root-help" || parsed.kind === "invalid") return defer("gh-read-only", "gh");
  if (parsed.kind === "help-topic") return parsed.disposition === "allow" ? allow("gh-read-only", "gh") : defer("gh-read-only", "gh");
  if (parsed.rule.path.join(" ") === "api") return { kind: "ignore" };
  if (parsed.rule.disposition !== "allow" || !ghCommandGrammarMatches(parsed)) return defer("gh-read-only", "gh");
  return allow("gh-read-only", "gh");
});
