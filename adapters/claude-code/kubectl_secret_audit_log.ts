// Claude Code hook: append an audit record when a Bash command that touched
// a Kubernetes Secret was actually allowed to run (PostToolUse only fires
// post-execution). Deliberately does NOT log the raw command text — commands
// like `kubectl create secret generic x --from-literal=password=...` carry
// the secret's actual value as a literal argv token.

import { homedir } from "node:os";
import { join } from "node:path";

import { analyzeBashWithPolicies, analyzeKubectlInvocation, appendAuditRecord, discoverWasmDir, initBashParser } from "../../src/index.js";

import { parseHookEvent, readStdin, run } from "./_shared.js";

const LOG_PATH = join(homedir(), ".claude", "logs", "kubectl-secret-audit.jsonl");

run(async () => {
  await initBashParser(discoverWasmDir(import.meta.url));
  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  if (!command) return;

  const summary = classifyKubectlSecretAudit(command);

  await appendAuditRecord(LOG_PATH, {
    timestamp: new Date().toISOString(),
    session_id: event.session_id ?? null,
    cwd: event.cwd ?? null,
    ...summary,
  });
});

export function classifyKubectlSecretAudit(command: string) {
  const analysis = analyzeBashWithPolicies({ source: command, policies: [], initialEnvironment: { kind: "unavailable" } });
  const invocation = analysis.events.find((event) => event.kind === "invocation"
    && event.executable?.kind === "known" && event.executable.value.split("/").at(-1) === "kubectl");
  if (!invocation || invocation.kind !== "invocation") return { kubectl_subcommand: null, resource: null, command_length: command.length };
  const decision = analyzeKubectlInvocation({ argv: invocation.argv });
  const kubectl = decision.kind === "ignore" ? undefined : decision.evidence.kubectl;
  return {
    kubectl_subcommand: kubectl?.subcommand ?? null,
    resource: kubectl?.resource ?? null,
    command_length: command.length,
  };
}
