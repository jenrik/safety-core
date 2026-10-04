import { buildGithubSuggestion, detectBlockedDomain } from "../../github.js";
import { GITHUB_GENERIC_HINT } from "../../messages.js";
import type { NormalizedCommand, ResolvedWord } from "../expand.js";
import { isBindingResolvedWord } from "../word-provenance.js";

export type GithubHttpPolicyDecision =
  | { readonly kind: "allow"; readonly evidence: { readonly name: "github-http"; readonly decision: "allow" } }
  | {
      readonly kind: "deny";
      readonly evidence: { readonly name: "github-http"; readonly decision: "deny"; readonly reason: string };
    };

/** The pure HTTP classifier only needs the resolved argument vector. */
export type GithubHttpInvocation = Pick<NormalizedCommand, "argv"> & {
  readonly argv: readonly ResolvedWord[];
};

export function analyzeGithubHttpInvocation(invocation: GithubHttpInvocation): GithubHttpPolicyDecision {
  for (const argument of invocation.argv) {
    if (argument.kind !== "known") {
      if (argument.reason.blockedGithubDomain) return deny(buildGithubHttpBlock(argument.reason.blockedGithubDomain));
      continue;
    }
    const domain = detectBlockedGithubDomain(argument.value);
    if (domain)
      return deny(
        isBindingResolvedWord(argument)
          ? "Blocked: direct GitHub HTTP request detected. Use the native gh command where possible."
          : buildGithubSuggestion(argument.value),
      );
  }
  return Object.freeze({ kind: "allow", evidence: Object.freeze({ name: "github-http", decision: "allow" }) });
}

export function detectBlockedGithubDomain(raw: string): string | null {
  return detectBlockedDomain(raw);
}

export function buildGithubHttpBlock(domain: string): string {
  return (
    `Blocked: direct HTTP request to ${domain} detected.\n\n` +
    "Use the native gh command where possible.\n\n" +
    `${GITHUB_GENERIC_HINT}\n\n` +
    "For raw file content, `gh api` is the GitHub CLI fallback because gh has no native file-read subcommand:\n" +
    "  gh api 'repos/<owner>/<repo>/contents/<path>?ref=<ref>' | jq -r '.content' | base64 -d\n\n" +
    "For multiple files, use the native gh repo clone subcommand:\n" +
    "  gh repo clone <owner>/<repo> /tmp/agent/<repo> -- --filter=blob:none"
  );
}

function deny(reason: string): GithubHttpPolicyDecision {
  return Object.freeze({ kind: "deny", evidence: Object.freeze({ name: "github-http", decision: "deny", reason }) });
}
