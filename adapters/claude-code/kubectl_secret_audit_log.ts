// Claude Code hook: append an audit record when a Bash command that touched
// a Kubernetes Secret was actually allowed to run (PostToolUse only fires
// post-execution). Deliberately does NOT log the raw command text — commands
// like `kubectl create secret generic x --from-literal=password=...` carry
// the secret's actual value as a literal argv token.

import { homedir } from "node:os";
import { join } from "node:path";

import { appendAuditRecord } from "../../src/index.js";

import { parseHookEvent, readStdin, run } from "./_shared.js";

const LOG_PATH = join(homedir(), ".claude", "logs", "kubectl-secret-audit.jsonl");

run(async () => {
  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  if (!command) return;

  // This matcher is an audit-only hook. It deliberately does not initialize
  // or reload policy configuration after the pre-execution decision boundary.
  const summary = {
    kubectl_subcommand: null,
    resource: null,
    command_length: command.length,
  };

  await appendAuditRecord(LOG_PATH, {
    timestamp: new Date().toISOString(),
    session_id: event.session_id ?? null,
    cwd: event.cwd ?? null,
    ...summary,
  });
});
