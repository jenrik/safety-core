// Canonical operator-facing messages used by every harness adapter.
// TODO: Keep only cross-harness policy text here; move the Claude-only secret
// fallback and GitHub-specific fallback hints next to their emitting handlers.

export const SECRET_BLOCK_MESSAGE = `Blocked by secrets-policy safety hook.

This file appears to contain secret values. Reading it would put those values into the conversation.

Allowed alternatives (do not reveal values):
  ls / test -f / stat                          existence
  wc -l                                        line count
  file FILE                                    file type
  grep -E '^[A-Z_]+=' FILE | cut -d= -f1       env var names only
  grep -c '<key-name>' FILE                    presence of a key

Structure (key names) is not confidential; values are.
To create or update: use shell redirection (>, >>) — never re-read to verify; use grep on key names or wc -l instead.

If this file is a placeholder/template (e.g. *.env.example), the hook would have allowed it. If you believe this is a false positive, consider renaming the file.`;

export const SECRETS_POLICY_FALLBACK = `# Secrets policy (fallback — canonical file missing)
Never read files containing secret values with tools that emit content (Read, cat, head, tail, less, bat, source). Use ls, test -f, wc -l, stat, or grep on key names instead. Structure is not confidential; values are.
`;

export const SECRET_COMMAND_REMINDER =
  "If the output above contains secrets, immediately stop and consult with the user on how to handle the secret leak.";

export const GITHUB_GENERIC_HINT = `Prefer native gh commands where possible (always prefer over direct API):
  gh issue list/view  ·  gh pr list/view  ·  gh release list/view
  gh run list/view  ·  gh repo view  ·  gh search issues/repos/code
  gh label list  ·  gh workflow list  ·  gh gist list

Use \`gh api <path>\` only when no native subcommand covers your use case.`;

export function buildSecretBlockMessage(reason: string): string {
  return `BLOCKED by secrets-policy safety hook: ${reason}\n\n${SECRET_BLOCK_MESSAGE}`;
}
