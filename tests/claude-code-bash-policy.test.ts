import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  evaluateConfiguredBash,
  initBashParser,
  STRICT_BASH_PROFILE_EXECUTABLES,
  type BashConfiguredEvaluation,
  type BashConfiguredOptions,
  type BashProfileSnapshot,
} from "../src/index.ts";
import { evaluateClaudeBashPolicy, isBashPreToolUse } from "../adapters/claude-code/_bash_policy.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-claude-bash-policy-"));
const limits = Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 });

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  copyFileSync(
    existsSync(join(process.cwd(), "tree-sitter-bash.wasm")) ? join(process.cwd(), "tree-sitter-bash.wasm") : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

function snapshot(overrides: Partial<BashProfileSnapshot> = {}): BashProfileSnapshot {
  return Object.freeze({
    readOnlyBash: false,
    ghApiReadOnly: false,
    ghReadOnly: false,
    helmReadOnly: false,
    strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
    ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
    limits,
    ...overrides,
  });
}

function event(command: string) {
  return { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } } as const;
}

function evaluate(command: string, profileSnapshot: BashProfileSnapshot) {
  let calls = 0;
  let options: BashConfiguredOptions | undefined;
  const decision = evaluateClaudeBashPolicy(event(command), {
    evaluateConfiguredBash(value) {
      calls++;
      options = value;
      return evaluateConfiguredBash({ ...value, profileSnapshot });
    },
  });
  return { calls, options, decision };
}

function fakeEvaluation(overrides: Partial<BashConfiguredEvaluation>): BashConfiguredEvaluation {
  return {
    guards: Object.freeze({ kind: "pass", status: "complete", policies: Object.freeze([]) }),
    permission: Object.freeze({ kind: "ignore" }),
    profiles: Object.freeze({}),
    analysis: Object.freeze({ status: "complete", evidence: Object.freeze([]) }),
    audit: Object.freeze({ events: Object.freeze([]) }),
    ...overrides,
  } as BashConfiguredEvaluation;
}

describe("Claude configured Bash policy", () => {
  test("evaluates valid Bash callbacks once with an unavailable environment", () => {
    const result = evaluate("gh api user", snapshot({ ghApiReadOnly: true }));
    expect(result.calls).toBe(1);
    expect(result.options).toMatchObject({ source: "gh api user", initialEnvironment: { kind: "verified" }, profileSnapshot: expect.anything() });
    expect(result.decision).toMatchObject({ kind: "allow" });
    expect(isBashPreToolUse(event("id"))).toBe(true);
    expect(isBashPreToolUse({ hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "id" } })).toBe(false);
    expect(isBashPreToolUse({ hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { command: "id" } })).toBe(false);
  });

  test("gives proven denials precedence but never auto-allows incomplete analysis", () => {
    const guard = fakeEvaluation({
      guards: Object.freeze({ kind: "block", reason: "guard denied", policy: { name: "kubectl", decision: "deny", reason: "guard denied" }, policies: Object.freeze([]) }),
      permission: Object.freeze({ kind: "allow", profile: "ghReadOnly", reason: "would allow" }),
      analysis: Object.freeze({ status: "failure", evidence: Object.freeze([]) }),
    });
    const denied = evaluateClaudeBashPolicy(event("ignored"), { evaluateConfiguredBash: () => guard });
    expect(denied).toEqual({ kind: "deny", reason: "guard denied" });

    const permissionDeny = fakeEvaluation({
      permission: Object.freeze({ kind: "deny", profile: "ghApiReadOnly", reason: "write denied" }),
      analysis: Object.freeze({ status: "failure", evidence: Object.freeze([]) }),
    });
    expect(evaluateClaudeBashPolicy(event("ignored"), { evaluateConfiguredBash: () => permissionDeny }))
      .toEqual({ kind: "deny", reason: "write denied" });

    const incompleteAllow = fakeEvaluation({
      permission: Object.freeze({ kind: "allow", profile: "ghReadOnly", reason: "would allow" }),
      analysis: Object.freeze({ status: "indeterminate", evidence: Object.freeze([]) }),
    });
    expect(evaluateClaudeBashPolicy(event("ignored"), { evaluateConfiguredBash: () => incompleteAllow })).toBeUndefined();
  });

  test("maps guards and configured profiles without exposing command data", () => {
    for (const command of [
      "cat credentials.json",
      "cat < credentials.json",
      "curl https://api.github.com/user",
      "kubectl view-secret application",
    ]) expect(evaluate(command, snapshot()).decision, command).toMatchObject({ kind: "deny" });

    expect(evaluate("kubectl get Secret application", snapshot()).decision).toBeUndefined();
    expect(evaluate("gh pr create --repo github.com/acme/widgets --fill", snapshot({
      ghPrCreate: Object.freeze({ enabled: true, allowedRepositories: Object.freeze(["acme/widgets"]), allowedOrganizations: Object.freeze([]) }),
    })).decision).toMatchObject({ kind: "allow" });
    expect(evaluate("gh pr create --repo github.com/attacker/widgets --fill", snapshot({
      ghPrCreate: Object.freeze({ enabled: true, allowedRepositories: Object.freeze(["acme/widgets"]), allowedOrganizations: Object.freeze([]) }),
    })).decision).toMatchObject({ kind: "deny" });
    expect(evaluate("docker image ls", snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    })).decision).toMatchObject({ kind: "allow" });

    const result = evaluate("CANARY_VALUE=never-emit; curl https://api.github.com/user", snapshot());
    expect(JSON.stringify(result.decision)).not.toContain("CANARY_VALUE");
    expect(JSON.stringify(result.decision)).not.toContain("never-emit");
  });

  test("defers mixed profile ownership and malformed or exhausted programs", () => {
    const profiles = snapshot({
      ghReadOnly: true,
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    });
    expect(evaluate("gh label list; docker image ls", profiles).decision).toBeUndefined();
    expect(evaluate("docker image ls; gh label list", profiles).decision).toBeUndefined();
    expect(evaluate("if then", snapshot({ ghReadOnly: true })).decision).toBeUndefined();
    expect(evaluate("gh label list", snapshot({ ghReadOnly: true, limits: Object.freeze({ ...limits, maxSteps: 0 }) })).decision).toBeUndefined();
  });

  test("property: supported guard forms always deny and profile order cannot allow mixed commands", () => {
    const directViolations = [
      "VALUE=credentials.json; cat \"$VALUE\"",
      "cat < credentials.json",
    ];
    for (const violation of directViolations) {
      expect(evaluate(violation, snapshot()).decision, violation).toMatchObject({ kind: "deny" });
    }

    const wrappedViolations = [
      "cat credentials.json",
      "/bin/cat credentials.json",
      "curl --silent https://api.github.com/user",
      "/usr/bin/curl https://api.github.com/user",
      "kubectl -n default view-secret application",
      "/usr/bin/kubectl view-secret application",
    ];
    const wrappers = [
      (command: string) => command,
      (command: string) => `env -i ${command}`,
      (command: string) => `strace -f ${command}`,
      (command: string) => `sh -c '${command}'`,
      (command: string) => `if true; then ${command}; fi`,
      (command: string) => `(${command}) | true`,
    ];
    for (const violation of wrappedViolations) {
      for (const wrap of wrappers) {
        expect(evaluate(wrap(violation), snapshot()).decision, wrap(violation)).toMatchObject({ kind: "deny" });
      }
    }

    const profiles = snapshot({
      ghReadOnly: true,
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    });
    for (const gh of ["gh label list", "gh repo list"]) {
      for (const docker of ["docker image ls", "docker volume ls"]) {
        expect(evaluate(`${gh}; ${docker}`, profiles).decision).toBeUndefined();
        expect(evaluate(`${docker}; ${gh}`, profiles).decision).toBeUndefined();
      }
    }
  });
});

test("Claude Bash policy entrypoint fails fatally when its parser assets are unavailable", () => {
  const configHome = mkdtempSync(join(tmpdir(), "safety-core-claude-bash-policy-config-"));
  const hookRoot = mkdtempSync(join(tmpdir(), "safety-core-claude-bash-policy-hook-"));
  try {
    mkdirSync(join(configHome, "safety-core"));
    writeFileSync(join(configHome, "safety-core", "profiles.json"), JSON.stringify({ ghApiReadOnly: true }));
    mkdirSync(join(hookRoot, "adapters", "claude-code"), { recursive: true });
    copyFileSync("adapters/claude-code/bash_policy.ts", join(hookRoot, "adapters", "claude-code", "bash_policy.ts"));
    copyFileSync("adapters/claude-code/_bash_policy.ts", join(hookRoot, "adapters", "claude-code", "_bash_policy.ts"));
    copyFileSync("adapters/claude-code/_shared.ts", join(hookRoot, "adapters", "claude-code", "_shared.ts"));
    symlinkSync(join(process.cwd(), "src"), join(hookRoot, "src"));
    const result = spawnSync(process.execPath, [join(hookRoot, "adapters", "claude-code", "bash_policy.ts")], {
      cwd: process.cwd(),
      input: JSON.stringify(event("gh api user")),
      encoding: "utf8",
      env: { ...process.env, SAFETY_CORE_CONFIG_HOME: configHome },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Bash parser initialization failed");
  } finally {
    rmSync(configHome, { force: true, recursive: true });
    rmSync(hookRoot, { force: true, recursive: true });
  }
});
