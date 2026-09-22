// Claude Code hook: one configured, single-pass policy evaluation for Bash.

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  discoverWasmDir,
  initBashParser,
  loadPolicyRuntime,
  loadPolicyRuntimeManifest,
  policyRuntimeManifest,
  type LoadedPolicyRuntime,
  type PolicyRuntimeManifest,
} from "../../src/index.js";
import { evaluateClaudeBashPolicy, isBashPreToolUse } from "./_bash_policy.js";
import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const event = parseHookEvent(readStdin());
  if (!isBashPreToolUse(event)) return;

  await initBashParser(discoverWasmDir(import.meta.url));
  const decision = evaluateClaudeBashPolicy(event, { runtime: await loadClaudeSessionRuntime(event.session_id, event.cwd ?? process.cwd()) });
  if (decision?.kind === "allow") emitAllow(decision.reason);
  if (decision?.kind === "deny") emitDeny(decision.reason);
});

/** Persist configuration and source identity; each hook verifies that snapshot. */
export async function loadClaudeSessionRuntime(sessionID: unknown, cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const manifestPath = claudeManifestPath(sessionID, cwd, env);
  if (existsSync(manifestPath)) return loadPolicyRuntimeManifest(parseManifest(readFileSync(manifestPath, "utf8"), manifestPath));

  const lock = await acquireManifestLock(manifestPath);
  if (lock) {
    try {
      if (existsSync(manifestPath)) return loadPolicyRuntimeManifest(parseManifest(readFileSync(manifestPath, "utf8"), manifestPath));
      const runtime = await loadPolicyRuntime(cwd, env);
      const manifest = policyRuntimeManifest(runtime, cwd);
      const temporary = `${manifestPath}.${process.pid}.tmp`;
      writeFileSync(temporary, JSON.stringify(manifest), { flag: "wx" });
      renameSync(temporary, manifestPath);
      return runtime;
    } finally {
      rmSync(lock, { force: true, recursive: true });
    }
  }
  return loadPolicyRuntimeManifest(parseManifest(readFileSync(manifestPath, "utf8"), manifestPath));
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
  const identity = typeof sessionID === "string" && sessionID.length > 0 ? sessionID : `cwd:${cwd}`;
  return join(stateHome, "safety-core", "claude-policy-sessions", `${createHash("sha256").update(identity).digest("hex")}.json`);
}

function requireHome(env: Readonly<Record<string, string | undefined>>): string {
  if (!env.HOME) throw new Error("HOME is required when no safety-core state home is configured");
  return env.HOME;
}

function parseManifest(source: string, path: string): PolicyRuntimeManifest {
  try {
    const value = JSON.parse(source) as PolicyRuntimeManifest;
    if (value.version !== 2 || typeof value.cwd !== "string" || (value.projectRoot !== undefined && typeof value.projectRoot !== "string")
      || !Array.isArray(value.configurations) || !Array.isArray(value.sources) || !value.limits) throw new Error("invalid manifest schema");
    return value;
  } catch (error) {
    throw new Error(`${path}: cannot load immutable policy session manifest: ${error instanceof Error ? error.message : "invalid JSON"}`);
  }
}
