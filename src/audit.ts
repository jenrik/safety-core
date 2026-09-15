// Filesystem audit log helper shared by opencode + claude-code adapters.
// TODO: Replace kubectl-specific filesystem logging with policy-neutral audit
// events from the configured evaluator and adapter-provided persistence sinks.

import { appendFile, chmod, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

export interface AuditRecord {
  timestamp: string;
  session_id?: string | null;
  cwd?: string | null;
  kubectl_subcommand?: string | null;
  resource?: string | null;
  command_length?: number;
}

/** Append a JSONL record to `path`, creating parent dirs and using mode 0600. */
export async function appendAuditRecord(path: string, record: AuditRecord): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  try {
    // A pre-existing log may have been created with a permissive mode. Correct
    // it before writing any record that could contain sensitive metadata.
    await chmod(path, 0o600);
  } catch (error) {
    if (!isMissing(error)) throw error;
  }
  await appendFile(path, JSON.stringify(sanitizeAuditRecord(record)) + "\n", { mode: 0o600 });
  await chmod(path, 0o600);
}

function sanitizeAuditRecord(record: AuditRecord): AuditRecord {
  const sanitized: AuditRecord = { timestamp: record.timestamp };
  if (record.session_id !== undefined) sanitized.session_id = record.session_id;
  if (record.cwd !== undefined) sanitized.cwd = record.cwd;
  if (record.kubectl_subcommand !== undefined) sanitized.kubectl_subcommand = record.kubectl_subcommand;
  if (record.resource !== undefined) sanitized.resource = record.resource;
  if (record.command_length !== undefined) sanitized.command_length = record.command_length;
  return sanitized;
}

function isMissing(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}
