import { expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

function runHook(path: string, input: unknown, env: NodeJS.ProcessEnv = process.env) {
  return spawnSync(process.execPath, [path], {
    cwd: process.cwd(),
    input: JSON.stringify(input),
    encoding: "utf8",
    env,
  });
}

test("Claude secrets handler retains session context and direct Read exit-2 blocks", () => {
  const home = mkdtempSync(join(tmpdir(), "safety-core-claude-secrets-"));
  try {
    const session = runHook("adapters/claude-code/secrets_policy.ts", { hook_event_name: "SessionStart" }, { ...process.env, HOME: home });
    expect(session.status).toBe(0);
    expect(session.stdout).toContain("secret");

    const read = runHook("adapters/claude-code/secrets_policy.ts", {
      hook_event_name: "PreToolUse",
      tool_name: "Read",
      tool_input: { file_path: "credentials.json" },
    }, { ...process.env, HOME: home });
    expect(read.status).toBe(2);
    expect(read.stdout).toBe("");
    expect(read.stderr).toContain("credentials.json");

    const bash = runHook("adapters/claude-code/secrets_policy.ts", {
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_input: { command: "cat credentials.json" },
    }, { ...process.env, HOME: home });
    expect(bash.status).toBe(0);
    expect(bash.stdout).toBe("");
  } finally {
    rmSync(home, { force: true, recursive: true });
  }
});

test("Claude SessionStart creates the immutable policy manifest before Bash callbacks", () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-claude-session-start-"));
  const home = join(root, "home");
  const state = join(root, "state");
  const policy = join(root, "policy.policy.mjs");
  try {
    mkdirSync(join(home, "safety-core"), { recursive: true });
    writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
    writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({
      version: 1,
      policies: [policy],
      projectPolicies: { mode: "disabled" },
      bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 },
    }));
    const session = runHook("adapters/claude-code/bash_policy.ts", {
      hook_event_name: "SessionStart",
      session_id: "session-start",
      cwd: root,
    }, { ...process.env, SAFETY_CORE_CONFIG_HOME: home, SAFETY_CORE_STATE_HOME: state });
    expect(session.status).toBe(0);
    const manifests = join(state, "safety-core", "claude-policy-sessions");
    expect(existsSync(manifests)).toBeTrue();
    const names = readdirSync(manifests);
    expect(names).toHaveLength(1);
    expect(JSON.parse(readFileSync(join(manifests, names[0]!), "utf8"))).toMatchObject({
      version: 1,
      sessionID: "session-start",
      cwd: root,
      configurations: [{ canonicalPath: join(home, "safety-core", "config.json"), sha256: expect.any(String) }],
      sources: [{ canonicalPath: policy, sha256: expect.any(String) }],
    });
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("Claude GitHub handler limits parsing and fallback enforcement to WebFetch", () => {
  const webFetch = runHook("adapters/claude-code/github_raw_redirect.ts", {
    hook_event_name: "PreToolUse",
    tool_name: "WebFetch",
    tool_input: { url: "https://api.github.com/user" },
  });
  expect(webFetch.status).toBe(0);
  expect(webFetch.stdout).toContain('"permissionDecision":"deny"');
  expect(webFetch.stderr).toBe("");

  const canary = "safety-core-auth-canary";
  const redacted = runHook("adapters/claude-code/github_raw_redirect.ts", {
    hook_event_name: "PreToolUse",
    tool_name: "WebFetch",
    tool_input: { url: `https://API.GITHUB.COM/user?access_token=${canary}#${canary}` },
  });
  expect(redacted.stdout).toContain('"permissionDecision":"deny"');
  expect(redacted.stdout).not.toContain(canary);

  const malformed = spawnSync(process.execPath, ["adapters/claude-code/github_raw_redirect.ts"], {
    cwd: process.cwd(),
    input: "not-json https://raw.githubusercontent.com/acme/widgets/main/README.md",
    encoding: "utf8",
  });
  expect(malformed.status).toBe(0);
  expect(malformed.stdout).toContain('"permissionDecision":"deny"');

  const postTool = runHook("adapters/claude-code/github_raw_redirect.ts", {
    hook_event_name: "PostToolUse",
    tool_name: "WebFetch",
    tool_input: { url: "https://api.github.com/user" },
  });
  expect(postTool.status).toBe(0);
  expect(postTool.stdout).toBe("");
});

test("Claude PostToolUse secret reminder emits only additional context", () => {
  const result = runHook("adapters/claude-code/secret_command_reminder.ts", {
    hook_event_name: "PostToolUse",
    tool_name: "Bash",
    tool_input: { command: "kubectl get Secret application" },
  });
  expect(result.status).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: expect.any(String),
    },
  });
  expect(result.stderr).toBe("");
});
