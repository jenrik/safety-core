// Claude Code hook: one configured, single-pass policy evaluation for Bash.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  discoverWasmDir,
  initBashParser,
  loadPolicyRuntime,
  createPolicySessionManifest,
  loadPolicySessionRuntime,
  parsePolicySessionManifest,
  type LoadedPolicyRuntime,
  type PolicySessionManifest,
} from "@safety-core/core";
import { evaluateClaudeBashPolicy, isBashPreToolUse } from "./_bash_policy.js";
import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const event = parseHookEvent(readStdin());
  if (event?.hook_event_name === "SessionStart") {
    await establishClaudeSessionRuntime(event.session_id, event.cwd ?? process.cwd());
    return;
  }
  if (!isBashPreToolUse(event)) return;

  await initBashParser(discoverWasmDir(import.meta.url));
  const cwd = event.cwd ?? process.cwd();
  const runtime = await loadClaudeSessionRuntime(event.session_id, cwd);
  let decision;
  try {
    decision = evaluateClaudeBashPolicy(event, { runtime });
  } catch (error) {
    poisonClaudeSession(event.session_id, cwd, error);
    throw error;
  }
  if (decision?.kind === "allow") emitAllow(decision.reason);
  if (decision?.kind === "deny") emitDeny(decision.reason);
});

/** Persist configuration and source identity during the one SessionStart event. */
export async function establishClaudeSessionRuntime(sessionID: unknown, cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const manifestPath = claudeManifestPath(sessionID, cwd, env);
  const poisonPath = claudePoisonPath(manifestPath);
  if (existsSync(poisonPath)) throw new Error(readFileSync(poisonPath, "utf8"));
  if (existsSync(manifestPath)) return reloadClaudeSessionRuntime(manifestPath, sessionID, cwd, env);

  const lock = await acquireManifestLock(manifestPath);
  if (lock) {
    try {
      if (existsSync(poisonPath)) throw new Error(readFileSync(poisonPath, "utf8"));
      if (existsSync(manifestPath)) return reloadClaudeSessionRuntime(manifestPath, sessionID, cwd, env);
      const runtime = await loadPolicyRuntime(cwd, env);
      const manifest = createPolicySessionManifest(sessionIdentity(sessionID, cwd), runtime, cwd);
      const temporary = `${manifestPath}.${process.pid}.tmp`;
      writeFileSync(temporary, JSON.stringify(manifest), { flag: "wx" });
      renameSync(temporary, manifestPath);
      return runtime;
    } finally {
      rmSync(lock, { force: true, recursive: true });
    }
  }
  return reloadClaudeSessionRuntime(manifestPath, sessionID, cwd, env);
}

/** Load only the SessionStart snapshot; PreToolUse must never select live policy. */
export async function loadClaudeSessionRuntime(sessionID: unknown, cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const manifestPath = claudeManifestPath(sessionID, cwd, env);
  if (!existsSync(manifestPath)) {
    throw new Error(`${manifestPath}: immutable policy session manifest is missing; SessionStart must establish it before PreToolUse`);
  }
  const poisonPath = claudePoisonPath(manifestPath);
  if (existsSync(poisonPath)) throw new Error(readFileSync(poisonPath, "utf8"));
  return reloadClaudeSessionRuntime(manifestPath, sessionID, cwd, env);
}

/** Persist a policy evaluation failure so every later hook invocation hard-fails. */
export function poisonClaudeSession(sessionID: unknown, cwd: string, error: unknown, env: Readonly<Record<string, string | undefined>> = process.env): void {
  const manifestPath = claudeManifestPath(sessionID, cwd, env);
  const path = claudePoisonPath(manifestPath);
  const reason = error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
  mkdirSync(dirname(path), { recursive: true });
  try {
    writeFileSync(path, reason, { flag: "wx" });
  } catch (writeError) {
    if ((writeError as NodeJS.ErrnoException).code !== "EEXIST") throw writeError;
  }
}

async function reloadClaudeSessionRuntime(
  manifestPath: string,
  sessionID: unknown,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
): Promise<LoadedPolicyRuntime> {
  try {
    return await loadPolicySessionRuntime(readManifest(manifestPath, sessionIdentity(sessionID, cwd)));
  } catch (error) {
    // Drift is terminal for this session, even if original bytes are restored.
    poisonClaudeSession(sessionID, cwd, error, env);
    throw error;
  }
}

/** An exclusive directory lock serializes first-session config/source selection. */
async function acquireManifestLock(manifestPath: string): Promise<string | undefined> {
  const lock = `${manifestPath}.lock`;
  mkdirSync(dirname(manifestPath), { recursive: true });
  for (let attempt = 0; attempt < 500; attempt++) {
    try {
      mkdirSync(lock);
      return lock;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      if (existsSync(manifestPath)) return undefined;
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }
  throw new Error(`${manifestPath}: timed out waiting for immutable policy session manifest`);
}

function claudeManifestPath(sessionID: unknown, cwd: string, env: Readonly<Record<string, string | undefined>>): string {
  const stateHome = env.SAFETY_CORE_STATE_HOME ?? env.XDG_STATE_HOME ?? join(requireHome(env), ".local", "state");
  return join(stateHome, "safety-core", "claude-policy-sessions", `${createHash("sha256").update(sessionIdentity(sessionID, cwd)).digest("hex")}.json`);
}

function requireHome(env: Readonly<Record<string, string | undefined>>): string {
  if (!env.HOME) throw new Error("HOME is required when no safety-core state home is configured");
  return env.HOME;
}

function readManifest(path: string, expectedSessionID: string): PolicySessionManifest {
  try {
    const manifest = parsePolicySessionManifest(JSON.parse(readFileSync(path, "utf8")));
    if (manifest.sessionID !== expectedSessionID) throw new Error("session ID does not match manifest key");
    return manifest;
  } catch (error) {
    throw new Error(`${path}: cannot load immutable policy session manifest: ${error instanceof Error ? error.message : "invalid JSON"}`);
  }
}

function claudePoisonPath(manifestPath: string): string {
  return `${manifestPath}.poison`;
}

function sessionIdentity(sessionID: unknown, cwd: string): string {
  return typeof sessionID === "string" && sessionID.length > 0 ? sessionID : `cwd:${cwd}`;
}
