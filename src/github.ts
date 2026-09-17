// Block direct HTTP requests to raw.githubusercontent.com and api.github.com,
// steering agents toward `gh` CLI equivalents.
// The Bash compatibility facade remains until Slice 6; Claude Code uses the
// configured evaluator and keeps malformed-event fallback handling in its adapter.

import { BLOCKED_GITHUB_DOMAINS } from "./patterns.js";
import { GITHUB_GENERIC_HINT } from "./messages.js";

const RAW_URL_RE =
  /https?:\/\/raw\.githubusercontent\.com\/([^/\s"']+)\/([^/\s"']+)\/([^/\s"']+)\/([^\s"'#?]+)/i;
const API_URL_RE = /https?:\/\/api\.github\.com(\/[^\s"'#?]*)?/i;

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
  const safeUrl = sanitizedBlockedGithubUrl(url);
  return safeUrl.includes("raw.githubusercontent.com")
    ? buildRawSuggestion(safeUrl)
    : buildApiSuggestion(safeUrl);
}

/** True iff `url` targets one of the blocked GitHub domains. */
export function isBlockedGithubUrl(url: string): boolean {
  return detectBlockedDomain(url) !== null;
}

/** Return reason string for a blocked WebFetch URL, or null. */
export function checkWebfetchUrl(url: string): string | null {
  return isBlockedGithubUrl(url) ? buildGithubSuggestion(url) : null;
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
  try {
    const parsed = new URL(raw);
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if ((parsed.protocol === "http:" || parsed.protocol === "https:") && BLOCKED_GITHUB_DOMAINS.includes(hostname)) return hostname;
  } catch {
    // Command arguments may contain a URL alongside flags or other text.
  }
  for (const domain of BLOCKED_GITHUB_DOMAINS) {
    const escaped = domain.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:^|[^a-z0-9.-])${escaped}(?=$|[^a-z0-9.-])`, "i").test(raw)) return domain;
  }
  return null;
}

/** Match relative or absolute GitHub GraphQL endpoint spellings without retaining query data. */
export function isGithubGraphqlEndpoint(endpoint: string): boolean {
  const path = endpoint.replace(/^(?:https?:)?\/\/[^/]+/i, "");
  return /^\/?graphql(?:\/|\?|#|$)/i.test(path);
}

function sanitizedBlockedGithubUrl(raw: string): string {
  const domain = detectBlockedDomain(raw);
  if (!domain) return "https://github.com/";
  try {
    const parsed = new URL(raw);
    return `https://${domain}${parsed.pathname || "/"}`;
  } catch {
    return `https://${domain}/`;
  }
}
