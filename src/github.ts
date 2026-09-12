// Block direct HTTP requests to raw.githubusercontent.com and api.github.com,
// steering agents toward `gh` CLI equivalents.

import { BLOCKED_GITHUB_DOMAINS } from "./patterns.js";
import { GITHUB_GENERIC_HINT } from "./messages.js";
import { analyzeBashAuthorization } from "./authorization.js";

const RAW_URL_RE =
  /https?:\/\/raw\.githubusercontent\.com\/([^/\s"']+)\/([^/\s"']+)\/([^/\s"']+)\/([^\s"'#?]+)/;
const API_URL_RE = /https?:\/\/api\.github\.com(\/[^\s"'#?]*)?/;

// API path → native gh command, tried in order. First match wins. Fail-open:
// if the mapping throws, callers get the generic hint.
const API_PATTERNS: Array<[RegExp, (m: RegExpMatchArray) => string]> = [
  [/^\/repos\/([^/]+)\/([^/]+)\/issues\/(\d+)/, (m) => `gh issue view ${m[3]} --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/issues(?:\/|$)/, (m) => `gh issue list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/pulls\/(\d+)/, (m) => `gh pr view ${m[3]} --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/pulls(?:\/|$)/, (m) => `gh pr list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/releases\/latest/, (m) => `gh release view --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/releases\/tags\/([^\s/]+)/, (m) => `gh release view ${m[3]} --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/releases(?:\/|$)/, (m) => `gh release list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/actions\/runs\/(\d+)/, (m) => `gh run view ${m[3]} --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/actions\/runs(?:\/|$)/, (m) => `gh run list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/actions\/workflows(?:\/|$)/, (m) => `gh workflow list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)\/labels(?:\/|$)/, (m) => `gh label list --repo ${m[1]}/${m[2]}`],
  [/^\/repos\/([^/]+)\/([^/]+)$/, (m) => `gh repo view ${m[1]}/${m[2]}`],
  [/^\/search\/issues/, () => "gh search issues <query>"],
  [/^\/search\/repositories/, () => "gh search repos <query>"],
  [/^\/search\/code/, () => "gh search code <query>"],
  [/^\/gists(?:\/|$)/, () => "gh gist list"],
];

function nativeCmdForPath(path: string): string | null {
  try {
    for (const [regex, build] of API_PATTERNS) {
      const m = path.match(regex);
      if (m) return build(m);
    }
  } catch {
    // fail-open — caller falls back to the generic hint
  }
  return null;
}

function buildRawSuggestion(url: string): string {
  const m = url.match(RAW_URL_RE);
  if (!m) {
    return (
      `Blocked: ${url}\n\n` +
      "Use gh CLI for single files:\n" +
      "  gh api repos/<owner>/<repo>/contents/<path>?ref=<ref> | jq -r '.content' | base64 -d\n\n" +
      "Or clone for multiple files:\n" +
      "  git clone --depth=1 https://github.com/<owner>/<repo>.git /tmp/agent/<repo>"
    );
  }
  const [, owner, repo, ref, path] = m;
  return (
    `Blocked: ${url}\n\n` +
    "Option 1 — single file via gh:\n" +
    `  gh api repos/${owner}/${repo}/contents/${path}?ref=${ref} | jq -r '.content' | base64 -d\n\n` +
    "Option 2 — multiple files (clone repo):\n" +
    `  git clone --depth=1 https://github.com/${owner}/${repo}.git /tmp/agent/${repo}\n` +
    `  # then read files directly from /tmp/agent/${repo}/`
  );
}

function buildApiSuggestion(url: string): string {
  const m = url.match(API_URL_RE);
  const path = m?.[1] ?? "";
  const native = nativeCmdForPath(path);
  if (native) {
    return (
      `Blocked: ${url}\n\n` +
      "Use the native gh command:\n" +
      `  ${native}\n\n` +
      "Only fall back to `gh api` if the native subcommand doesn't suffice:\n" +
      `  gh api '${path}'`
    );
  }
  return (
    `Blocked: ${url}\n\n${GITHUB_GENERIC_HINT}\n\n` + `  gh api '${path}'`
  );
}

/** Build the operator-facing block message for a specific blocked URL. */
export function buildGithubSuggestion(url: string): string {
  return url.includes("raw.githubusercontent.com")
    ? buildRawSuggestion(url)
    : buildApiSuggestion(url);
}

/** True iff `url` targets one of the blocked GitHub domains. */
export function isBlockedGithubUrl(url: string): boolean {
  return BLOCKED_GITHUB_DOMAINS.some((d) => url.includes(d));
}

/** Return reason string for a blocked WebFetch URL, or null. */
export function checkWebfetchUrl(url: string): string | null {
  return isBlockedGithubUrl(url) ? buildGithubSuggestion(url) : null;
}

/**
 * Return reason string if `command` invokes an HTTP tool against a blocked
 * GitHub URL, else null. The stateful authorization walker resolves only
 * statically knowable invocation arguments; unavailable parsing stays neutral.
 */
export function checkBashForGithub(command: string): string | null {
  const policy = analyzeBashAuthorization({ source: command }).policies
    .find((evidence) => evidence.name === "github-http" && evidence.decision === "deny");
  return policy?.reason ?? null;
}

/** Fallback deny message when we can't parse the tool payload but a blocked
 * domain is textually present. */
export function buildFallbackGithubBlock(domain: string): string {
  return (
    `Blocked: direct HTTP request to ${domain} detected.\n\n` +
    `${GITHUB_GENERIC_HINT}\n\n` +
    "For raw file content use:\n" +
    "  gh api repos/<owner>/<repo>/contents/<path>?ref=<ref> | jq -r '.content' | base64 -d\n" +
    "  git clone --depth=1 https://github.com/<owner>/<repo>.git /tmp/agent/<repo>"
  );
}

/** True iff any blocked domain appears anywhere in `raw`. */
export function detectBlockedDomain(raw: string): string | null {
  for (const domain of BLOCKED_GITHUB_DOMAINS) {
    if (raw.includes(domain)) return domain;
  }
  return null;
}
