// Claude Code hook: append an audit record when a Bash command that touched
// a Kubernetes Secret was actually allowed to run (PostToolUse only fires
// post-execution). Deliberately does NOT log the raw command text — commands
// like `kubectl create secret generic x --from-literal=password=...` carry
// the secret's actual value as a literal argv token.

import { homedir } from "node:os";
import { join } from "node:path";

import { appendAuditRecord, summariseKubectlSecret } from "../../src/index.js";

import { parseHookEvent, readStdin, run } from "./_shared.js";

const LOG_PATH = join(homedir(), ".claude", "logs", "kubectl-secret-audit.jsonl");

run(async () => {
  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  if (!command) return;

  // The hook is wired against `Bash(*secret*)` in settings, so ANY match is
  // worth logging (even non-kubectl commands that happened to mention a
  // secret-shaped word). summariseKubectlSecret returns null when the command
  // isn't a Secret-touching kubectl call; in that case log a minimal record.
  const summary = summariseKubectlSecret(command) ?? {
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
