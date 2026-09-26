// Claude Code hook: append an audit record when a Bash command that touched
// a Kubernetes Secret was actually allowed to run (PostToolUse only fires
// post-execution). Deliberately does NOT log the raw command text — commands
// like `kubectl create secret generic x --from-literal=password=...` carry
// the secret's actual value as a literal argv token.

import { homedir } from "node:os";
import { join } from "node:path";

import { analyzeBashWithPolicies, analyzeKubectlInvocation, appendAuditRecord, discoverWasmDir, initBashParser } from "@safety-core/core";

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
  const candidates: { readonly decision: ReturnType<typeof analyzeKubectlInvocation> }[] = [];
  for (const event of analysis.events) {
    if (event.kind !== "invocation" || event.executable?.kind !== "known" || event.executable.value.split("/").at(-1) !== "kubectl") continue;
    candidates.push({ decision: analyzeKubectlInvocation({ argv: event.argv }) });
  }
  const selected = candidates.find(({ decision }) => decision.kind !== "ignore" && decision.evidence.kubectl?.mentionsSecret) ?? candidates[0];
  const kubectl = selected?.decision.kind === "ignore" ? undefined : selected?.decision.evidence.kubectl;
  return {
    kubectl_subcommand: kubectl?.subcommand ?? null,
    resource: kubectl?.resource ?? null,
    command_length: command.length,
  };
}
