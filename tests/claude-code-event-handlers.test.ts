import { expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
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

test("Claude GitHub handler limits parsing and fallback enforcement to WebFetch", () => {
  const webFetch = runHook("adapters/claude-code/github_raw_redirect.ts", {
    hook_event_name: "PreToolUse",
    tool_name: "WebFetch",
    tool_input: { url: "https://api.github.com/user" },
  });
  expect(webFetch.status).toBe(0);
  expect(webFetch.stdout).toContain('"permissionDecision":"deny"');
  expect(webFetch.stderr).toBe("");

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
