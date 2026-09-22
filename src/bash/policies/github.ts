import type { NormalizedCommand, ResolvedWord } from "../expand.js";
import { isBindingResolvedWord } from "../word-provenance.js";
import { GITHUB_GENERIC_HINT } from "../../messages.js";
import { buildGithubSuggestion, detectBlockedDomain } from "../../github.js";

export type GithubHttpPolicyDecision =
  | { readonly kind: "allow"; readonly evidence: { readonly name: "github-http"; readonly decision: "allow" } }
  | { readonly kind: "deny"; readonly evidence: { readonly name: "github-http"; readonly decision: "deny"; readonly reason: string } };

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
    if (domain) return deny(isBindingResolvedWord(argument)
      ? "Blocked: direct GitHub HTTP request detected. Use the native gh command where possible."
      : buildGithubSuggestion(argument.value));
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
    "For raw file content use:\n" +
    "  gh api repos/<owner>/<repo>/contents/<path>?ref=<ref> | jq -r '.content' | base64 -d\n" +
    "  git clone --depth=1 https://github.com/<owner>/<repo>.git /tmp/agent/<repo>"
  );
}

function deny(reason: string): GithubHttpPolicyDecision {
  return Object.freeze({ kind: "deny", evidence: Object.freeze({ name: "github-http", decision: "deny", reason }) });
}
