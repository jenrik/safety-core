import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { main } from "../src/cli.ts";

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
  test("packaged CLI validates and explains the scoped redirect-input fixture", () => {
    const home = fixture();
    const policy = join(process.cwd(), "tests/fixtures/redirect-input.policy.json");
    const config = join(home, "safety-core/config.json");
    writeFileSync(config, JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "disabled" },
      bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 } }));
    const packaged = (args: readonly string[]) => spawnSync("node", [join(process.cwd(), "packages/core/dist/cli.js"), "--config", config, ...args], {
      encoding: "utf8", env: { PATH: process.env.PATH ?? "" },
    });
    const validated = packaged(["validate"]);
    expect(validated.status).toBe(0);
    expect(validated.stdout).toMatch(/^[a-f0-9]{64}  \/.*redirect-input\.policy\.json\n$/);
    for (const [source, expected] of [['redirect-fixture <<<"accepted"', "allow"], ['redirect-fixture <<<"different"', "defer"],
      ['redirect-fixture <<<"forbidden"', "deny"], ['> output; redirect-fixture <<<"accepted"', "defer"],
      ["redirect-fixture < /review/trusted.yaml", "defer"]] as const) {
      const explained = packaged(["explain", "--json", "--", source]);
      expect(explained.status, source).toBe(0);
      const trace = JSON.parse(explained.stdout);
      expect(trace.decision, source).toBe(expected);
      expect(trace.sources, source).toHaveLength(1);
      expect(trace.sources[0].canonicalPath, source).toBe(policy);
      if (source.includes("<<<")) {
        expect(trace.events.some((event: any) => event.kind === "invocation" && event.redirects.some((redirect: any) => redirect.kind === "here-string")), source).toBeTrue();
      }
      if (source.startsWith("> output")) {
        expect(trace.events[0].executable).toBeNull();
        expect(trace.fileAccesses).toHaveLength(1);
        expect(trace.fileAccesses[0].operation).toBe("write");
      }
    }
  }, 30_000);

  test("an explicit config path overrides the environment-selected configuration", () => {
    const home = fixture();
    const config = join(home, "safety-core", "config.json");
    const result = cli(join(home, "missing"), ["--config", config, "validate"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^[a-f0-9]{64}  \/.*canary\.policy\.mjs\n$/);
  });

  test("property: both config flag forms work before or after the command", async () => {
    const home = fixture();
    const config = join(home, "safety-core", "config.json");
    writeFileSync(config, JSON.stringify({
      version: 1,
      policies: [],
      projectPolicies: { mode: "disabled" },
      bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 50, maxWorkItems: 50 },
    }));
    for (let seed = 0; seed < 1_024; seed++) {
      const option = seed % 2 === 0 ? ["--config", config] : [`--config=${config}`];
      const args = seed % 4 < 2 ? [...option, "validate"] : ["validate", ...option];
      await expect(main(args), `seed ${seed}`).resolves.toBeUndefined();
    }
  });

  test("rejects missing or empty global config paths", () => {
    const home = fixture();
    for (const args of [["--config"], ["--config=", "validate"]]) {
      const result = cli(home, args);
      expect(result.status, JSON.stringify(args)).not.toBe(0);
      expect(result.stderr, JSON.stringify(args)).toContain("--config");
    }
  });

  test("the final repeated global config option wins", () => {
    const home = fixture();
    const config = join(home, "safety-core", "config.json");
    const result = cli(home, ["--config", join(home, "missing-config.json"), "--config", config, "validate"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^[a-f0-9]{64}  \/.*canary\.policy\.mjs\n$/);
  });

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
    const result = cli(home, ["explain", "--json", "CANARY_ASSIGN=exact-value printf '%s' CANARY_ARG"], { CANARY_INHERITED: "inherited-value" });
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

    const result = cli(home, ["explain", "--json", "printf CANARY_ARG"], { CANARY_INHERITED: "exact-inherited-value" });
    expect(result.status).toBe(0);
    const trace = JSON.parse(result.stdout);
    expect(trace).toMatchObject({ version: 1, decision: "allow", analysis: { complete: true } });
    expect(trace.events[0].argv).toEqual([{ kind: "known", value: "CANARY_ARG" }]);
    expect(trace.events[0].environment.CANARY_INHERITED).toEqual({ kind: "known", value: "exact-inherited-value" });
    expect(trace.events[0].missingBindings).toBe("unset");
    expect(trace.decisions[0].decision).toMatchObject({ kind: "allow", reason: [{ kind: "literal", value: "inherited environment canary" }] });
  });

  test("Commander validates subcommand options and treats values after -- as Bash source", () => {
    const home = fixture();
    const invalidValidate = cli(home, ["validate", "--json"]);
    expect(invalidValidate.status).not.toBe(0);
    expect(invalidValidate.stderr).toContain("--json");

    const sourceStartingWithOption = cli(home, ["explain", "--json", "--", "--config"]);
    expect(sourceStartingWithOption.status).toBe(0);
    expect(JSON.parse(sourceStartingWithOption.stdout)).toMatchObject({ version: 1, decision: "defer" });
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
