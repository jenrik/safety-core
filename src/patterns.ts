// Shared pattern lists for the LLM safety hook.
//
// These are the source of truth used by every harness adapter
// (claude-code, pi, opencode). Do not fork these lists into an adapter.

// ─── Secret files ────────────────────────────────────────────────────────────

// Filename globs treated as containing secret VALUES. Key names and file
// structure are not confidential; only the values are.
export const SECRET_PATTERNS: readonly string[] = [
  "*.env",
  "*.env.*",
  ".envrc",
  "*.pem",
  "*.key",
  "id_rsa*",
  "id_ed25519*",
  "id_dsa*",
  "id_ecdsa*",
  "*.p12",
  "*.pfx",
  "*.pkcs12",
  ".netrc",
  "credentials.json",
  "credentials.yaml",
  "credentials.yml",
  "*-credentials.json",
  "*-credentials.yaml",
  "*-credentials.yml",
  "*.credentials.json",
  "*.credentials.yaml",
  "*.credentials.yml",
  "service-account*.json",
  "service_account*.json",
  "secrets.json",
  "secrets.yaml",
  "secrets.yml",
  "*-secrets.json",
  "*-secrets.yaml",
  "*-secrets.yml",
  "*.secrets.json",
  "*.secrets.yaml",
  "*.secrets.yml",
  "*.secret.json",
  "*.secret.yaml",
  "*.secret.yml",
  "kubeconfig",
];

// Names that match SECRET_PATTERNS but are known-safe (templates/examples).
export const SECRET_EXCEPTIONS: readonly string[] = [
  "*.env.example",
  "*.env.sample",
  "*.env.template",
  "*.env.dist",
];

// Commands whose primary effect is emitting file content to stdout.
export const READING_COMMANDS: ReadonlySet<string> = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "bat",
  "more",
  "view",
  "xxd",
  "od",
  "hexdump",
  "strings",
  "source",
  ".",
]);

// ─── GitHub direct-HTTP block ────────────────────────────────────────────────

export const BLOCKED_GITHUB_DOMAINS: readonly string[] = [
  "raw.githubusercontent.com",
  "api.github.com",
];

// HTTP client executables considered when scanning a shell command.
export const HTTP_TOOLS: ReadonlySet<string> = new Set([
  "curl",
  "wget",
  "http",
  "httpie",
  "fetch",
  "httpx",
]);

// ─── kubectl ─────────────────────────────────────────────────────────────────

// kubectl flags that consume the NEXT token as their value (i.e. `--flag value`,
// not `--flag=value`). Used to correctly locate positional arguments.
export const KUBECTL_FLAGS_WITH_VALUES: ReadonlySet<string> = new Set([
  // Global
  "--context",
  "--kubeconfig",
  "--namespace",
  "-n",
  "--cluster",
  "--user",
  "--server",
  "--token",
  "--certificate-authority",
  "--client-certificate",
  "--client-key",
  "--as",
  "--as-group",
  "--as-uid",
  "--cache-dir",
  "--request-timeout",
  "--tls-server-name",
  // Output / selection
  "-o",
  "--output",
  "-l",
  "--selector",
  "--field-selector",
  "--chunk-size",
  "--sort-by",
  "--template",
  "--timeout",
  "--subresource",
  // logs
  "-c",
  "--container",
  "--since",
  "--since-time",
  "--tail",
  "--limit-bytes",
  // annotate / label
  "--field-manager",
]);

// Read-only kubectl subcommands that are unconditionally auto-allowed.
export const KUBECTL_ALWAYS_ALLOW: ReadonlySet<string> = new Set([
  "describe",
  "logs",
  "explain",
  "cluster-info",
  "top",
  "api-resources",
  "api-versions",
  "version",
  "events",
  "diff",
  "wait",
  "annotate",
]);

export const KUBECTL_SECRET_TYPES: ReadonlySet<string> = new Set([
  "secret",
  "secrets",
]);

export const KUBECTL_ROLLOUT_ALLOW: ReadonlySet<string> = new Set([
  "status",
  "history",
]);

export const KUBECTL_AUTH_ALLOW: ReadonlySet<string> = new Set([
  "can-i",
  "whoami",
]);
