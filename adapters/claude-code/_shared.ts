// Small stdin/stdout helpers shared by every Claude Code hook adapter.
//
// Every hook script reads a JSON event from stdin and produces one of:
//   - exit 0                    → "no opinion", let default rules decide
//   - exit 2 + stderr           → hard block; stderr is shown to the model
//   - stdout JSON with hookSpecificOutput → permissionDecision override
//   - stdout plain text (SessionStart) → additional context for the model
// Bash PreToolUse policy decisions are consolidated in bash_policy.ts. Other
// entries remain only for event-specific Read, WebFetch, SessionStart, and
// PostToolUse behavior.

import { readFileSync } from "node:fs";

export interface HookEvent {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
}

/** Read all of stdin synchronously. Empty on empty pipe. */
export function readStdin(): string {
  try {
    return readFileSync(0, "utf-8");
  } catch {
    return "";
  }
}

export function parseHookEvent(raw: string): HookEvent | null {
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw) as HookEvent;
  } catch {
    return null;
  }
}

/** Emit a native PreToolUse allow override on stdout and exit 0. */
export function emitAllow(reason: string): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "allow",
        permissionDecisionReason: reason,
      },
    }),
  );
}

/** Emit a native PreToolUse deny override on stdout and exit 0. */
export function emitDeny(reason: string): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason,
      },
    }),
  );
}

/** Emit a PostToolUse additionalContext injection and exit 0. */
export function emitPostContext(text: string): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: text,
      },
    }),
  );
}

/** Hard block direct reads with exit code 2 and an stderr-only reason. */
export function hardBlock(message: string): never {
  process.stderr.write(message);
  process.exit(2);
}

/**
 * Parser deployment failures are fatal. Other hook errors retain the existing
 * fail-open behavior so Claude Code can continue through native permissions.
 */
export function run(main: () => Promise<void> | void): void {
  Promise.resolve()
    .then(main)
    .catch((err) => {
      try {
        process.stderr.write(`[safety-hook] internal error: ${err}\n`);
      } catch {}
      process.exit(isBashParserFailure(err) ? 2 : 0);
    });
}

function isBashParserFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null
    && "code" in error && error.code === "SAFETY_CORE_BASH_PARSER_FAILURE";
}
