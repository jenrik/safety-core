// Filesystem audit log helper shared by opencode + claude-code adapters.
// TODO: Replace kubectl-specific filesystem logging with policy-neutral audit
// events from the configured evaluator and adapter-provided persistence sinks.

import { appendFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface AuditRecord {
  timestamp: string;
  session_id?: string | null;
  cwd?: string | null;
  kubectl_subcommand?: string | null;
  resource?: string | null;
  command_length?: number;
  [k: string]: unknown;
}

/** Append a JSONL record to `path`, creating parent dirs and using mode 0600. */
export async function appendAuditRecord(path: string, record: AuditRecord): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, JSON.stringify(record) + "\n", { mode: 0o600 });
}

/** Default audit-log path under $XDG_STATE_HOME (falling back to ~/.local/state). */
export function defaultAuditPath(agent: string): string {
  const base =
    process.env.XDG_STATE_HOME ??
    join(process.env.HOME ?? "", ".local", "state");
  return join(base, agent, "kubectl-secret-audit.jsonl");
}
