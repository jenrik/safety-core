// Small stdin/stdout helpers shared by every claude-code hook adapter.
//
// Every hook script reads a JSON event from stdin and produces one of:
//   - exit 0                    → "no opinion", let default rules decide
//   - exit 2 + stderr           → hard block; stderr is shown to the model
//   - stdout JSON with hookSpecificOutput → permissionDecision override
//   - stdout plain text (SessionStart) → additional context for the model
// TODO: Replace the separate Bash policy hook scripts with one adapter entry
// that delegates configured, single-pass Bash evaluation to the shared core.

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

/** Emit a PreToolUse allow decision and exit 0. */
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

/** Emit a PreToolUse deny decision and exit 0. */
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

/** Hard block: exit code 2 tells Claude Code to abort the tool call and
 *  surface the stderr contents to the model. */
export function hardBlock(message: string): never {
  process.stderr.write(message);
  process.exit(2);
}

/**
 * Parser deployment failures are fatal. Other hook errors retain the existing
 * fail-open behavior until the hooks are consolidated in a later slice.
 */
export function run(main: () => Promise<void> | void): void {
  Promise.resolve()
    .then(main)
    .catch((err) => {
      try {
        process.stderr.write(`[safety-hook] internal error: ${err}\n`);
      } catch {}
      process.exit(isBashParserFailure(err) ? 1 : 0);
    });
}

function isBashParserFailure(error: unknown): boolean {
  return typeof error === "object" && error !== null
    && "code" in error && error.code === "SAFETY_CORE_BASH_PARSER_FAILURE";
}
