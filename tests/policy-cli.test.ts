import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fixtures: string[] = [];

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), "safety-core-cli-"));
  fixtures.push(root);
  const config = join(root, "safety-core");
  mkdirSync(config, { recursive: true });
  const policy = join(root, "canary.policy.mjs");
  writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]), evaluate(event) { return event.kind === "invocation" && event.executable.kind === "known" && event.executable.value === "printf" ? { kind: "allow", reason: [{ kind: "literal", value: "canary allow" }] } : { kind: "ignore" }; } });\n`);
  writeFileSync(join(config, "config.json"), JSON.stringify({
    version: 1,
    policies: [policy],
    projectPolicies: { mode: "disabled" },
    bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 50, maxWorkItems: 50 },
  }));
  return root;
}

afterEach(() => {
  while (fixtures.length) rmSync(fixtures.pop()!, { force: true, recursive: true });
});

function cli(home: string, args: readonly string[], extraEnv: Record<string, string> = {}, cwd: string = process.cwd()) {
  return spawnSync("bun", [join(process.cwd(), "src/cli.ts"), ...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, SAFETY_CORE_CONFIG_HOME: home, ...extraEnv },
  });
}

describe("safety-core CLI", () => {
  test("validate reports canonical sources and digests and does not consult profiles.json", () => {
    const home = fixture();
    writeFileSync(join(home, "safety-core", "profiles.json"), "not json");
    const result = cli(home, ["validate"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^[a-f0-9]{64}  \/.*canary\.policy\.mjs\n$/);
  });

  test("missing authoritative configuration is fatal", () => {
    const home = mkdtempSync(join(tmpdir(), "safety-core-cli-missing-"));
    fixtures.push(home);
    const result = cli(home, ["validate"]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("config.json");
  });

  test("validate loads the nearest all-mode project DSL policy before starting", () => {
    const home = fixture();
    const project = join(home, "project");
    const projectConfig = join(project, ".safety-core");
    const policy = join(project, "project.policy.json");
    mkdirSync(projectConfig, { recursive: true });
    writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({
      version: 1,
      policies: [],
      projectPolicies: { mode: "all" },
      bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 50, maxWorkItems: 50 },
    }));
    writeFileSync(join(projectConfig, "config.json"), JSON.stringify({ version: 1, policies: ["project.policy.json"] }));
    writeFileSync(policy, JSON.stringify({
      language: "safety-core/bash-policy-v1", layer: "permission", select: [{ kind: "invocation" }], registers: {}, start: "start",
      states: { start: { cases: [], default: { decision: "ignore" }, end: { decision: "allow", reason: ["project allow"] } } },
    }));

    const result = cli(home, ["validate"], {}, project);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`  ${policy}\n`);
  });

  test("explain emits every source decision and the exact modeled canary argv and environment", () => {
    const home = fixture();
    const result = cli(home, ["explain", "--json", "--", "CANARY_ASSIGN=exact-value printf '%s' CANARY_ARG"], { CANARY_INHERITED: "inherited-value" });
    expect(result.status).toBe(0);
    const trace = JSON.parse(result.stdout);
    expect(trace).toMatchObject({ version: 1, decision: "allow" });
    expect(trace.sources).toHaveLength(1);
    expect(trace.events[0].argv).toEqual([{ kind: "known", value: "%s" }, { kind: "known", value: "CANARY_ARG" }]);
    expect(trace.events[0].environment.CANARY_ASSIGN).toEqual({ kind: "known", value: "exact-value" });
    expect(trace.events[0].environment.CANARY_INHERITED).toEqual({ kind: "known", value: "inherited-value" });
    expect(trace.decisions).toHaveLength(1);
  });

  test("a real DSL permission policy receives exact inherited environment values in unchanged explain traces", () => {
    const home = fixture();
    const policy = join(home, "environment.policy.json");
    writeFileSync(policy, JSON.stringify(environmentPermissionPolicy()));
    writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({
      version: 1,
      policies: [policy],
      projectPolicies: { mode: "disabled" },
      bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 50, maxWorkItems: 50 },
    }));

    const result = cli(home, ["explain", "--json", "--", "printf CANARY_ARG"], { CANARY_INHERITED: "exact-inherited-value" });
    expect(result.status).toBe(0);
    const trace = JSON.parse(result.stdout);
    expect(trace).toMatchObject({ version: 1, decision: "allow", analysis: { complete: true } });
    expect(trace.events[0].argv).toEqual([{ kind: "known", value: "CANARY_ARG" }]);
    expect(trace.events[0].environment.CANARY_INHERITED).toEqual({ kind: "known", value: "exact-inherited-value" });
    expect(trace.events[0].missingBindings).toBe("unset");
    expect(trace.decisions[0].decision).toMatchObject({ kind: "allow", reason: [{ kind: "literal", value: "inherited environment canary" }] });
  });
});

function environmentPermissionPolicy(): Record<string, unknown> {
  return {
    language: "safety-core/bash-policy-v1",
    layer: "permission",
    select: [{ kind: "invocation" }],
    registers: {}, folds: {}, options: {}, fragments: {}, start: "start",
    states: {
      start: {
        cases: [{
          when: { call: "environmentValueEquals", args: [{ call: "environmentLookup", args: ["CANARY_INHERITED"] }, "exact-inherited-value"] },
          action: { decision: "allow", reason: ["inherited environment canary"] },
        }],
        default: { decision: "defer" },
        end: { decision: "defer" },
      },
    },
  };
}
