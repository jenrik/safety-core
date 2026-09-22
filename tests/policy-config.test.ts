import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PolicyStartupError,
  loadGlobalPolicyConfig,
  resolveSessionPolicyConfig,
} from "../src/policy/config.ts";

function fixtureDirectory(): string {
  return mkdtempSync(join(tmpdir(), "safety-core-policy-config-"));
}

function writeGlobalConfig(home: string, value: unknown): string {
  const directory = join(home, "safety-core");
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "config.json");
  writeFileSync(path, JSON.stringify(value));
  return path;
}

function globalConfig(policies: readonly string[] = []): object {
  return {
    version: 1,
    policies,
    projectPolicies: { mode: "disabled" },
    bashAnalysis: {
      maxFunctionDepth: 7,
      maxNestedScriptDepth: 6,
      maxSteps: 5,
      maxWorkItems: 4,
    },
  };
}

describe("authoritative global policy configuration", () => {
  test("selects config-home variables by presence without missing-file fallback", () => {
    const root = fixtureDirectory();
    const safetyHome = join(root, "safety");
    const xdgHome = join(root, "xdg");
    const home = join(root, "home");
    writeGlobalConfig(xdgHome, globalConfig());
    writeGlobalConfig(join(home, ".config"), globalConfig());

    expect(() => loadGlobalPolicyConfig({
      SAFETY_CORE_CONFIG_HOME: safetyHome,
      XDG_CONFIG_HOME: xdgHome,
      HOME: home,
    })).toThrow(PolicyStartupError);

    const loaded = loadGlobalPolicyConfig({ XDG_CONFIG_HOME: xdgHome, HOME: home });
    expect(loaded.path).toBe(join(xdgHome, "safety-core", "config.json"));
  });

  test("treats malformed configuration and unavailable allowlist roots as fatal", () => {
    const home = fixtureDirectory();
    const path = writeGlobalConfig(home, globalConfig());
    writeFileSync(path, "{");
    expect(() => loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home })).toThrow(PolicyStartupError);

    writeGlobalConfig(home, {
      ...globalConfig(),
      projectPolicies: { mode: "allowlisted", allowedRoots: [join(home, "missing-root")] },
    });
    expect(() => resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), home)).toThrow(PolicyStartupError);
  });

  test("rejects empty or relative selected environment paths", () => {
    for (const env of [
      { SAFETY_CORE_CONFIG_HOME: "", HOME: "/home/test" },
      { SAFETY_CORE_CONFIG_HOME: "relative", HOME: "/home/test" },
      { XDG_CONFIG_HOME: "relative", HOME: "/home/test" },
      { HOME: "" },
      { HOME: "relative" },
    ]) expect(() => loadGlobalPolicyConfig(env), JSON.stringify(env)).toThrow(PolicyStartupError);
  });

  test("strictly parses only complete recognized global configuration", () => {
    const home = fixtureDirectory();
    for (const invalid of [
      { ...globalConfig(), unknown: true },
      { ...globalConfig(), version: 2 },
      { ...globalConfig(), policies: ["not-a-source.js"] },
      { ...globalConfig(), projectPolicies: { mode: "allowlisted" } },
      { ...globalConfig(), bashAnalysis: { maxSteps: 1 } },
    ]) {
      writeGlobalConfig(home, invalid);
      expect(() => loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), JSON.stringify(invalid)).toThrow(PolicyStartupError);
    }

    writeGlobalConfig(home, globalConfig(["policies/read.policy.mjs"]));
    const loaded = loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home });
    expect(loaded.bashAnalysis).toEqual({ maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 5, maxWorkItems: 4 });
    expect(Object.isFrozen(loaded)).toBeTrue();
    expect(Object.isFrozen(loaded.bashAnalysis)).toBeTrue();
  });

  test("resolves global references from their configuration and permits code or DSL sources", () => {
    const home = fixtureDirectory();
    const configPath = writeGlobalConfig(home, globalConfig(["policies/read.policy.mjs", "/installed/absolute.policy.mjs"]));
    const loaded = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), fixtureDirectory());

    expect(loaded.sources.map((source) => source.path)).toEqual([
      join(configPath, "..", "policies", "read.policy.mjs"),
      "/installed/absolute.policy.mjs",
    ]);
    expect(Object.isFrozen(loaded)).toBeTrue();
    expect(Object.isFrozen(loaded.sources)).toBeTrue();

    writeGlobalConfig(home, globalConfig(["policies/read.policy.json"]));
    expect(resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), fixtureDirectory()).sources)
      .toEqual([{ path: join(configPath, "..", "policies", "read.policy.json"), scope: "global" }]);
  });

  test("discovers only the nearest permitted project config and rejects code policy references", () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const project = join(root, "project");
    const child = join(project, "nested", "cwd");
    mkdirSync(join(project, ".safety-core"), { recursive: true });
    mkdirSync(join(child, ".safety-core"), { recursive: true });
    writeFileSync(join(project, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: ["parent.policy.json"] }));
    writeFileSync(join(child, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: ["child.policy.json"] }));
    writeGlobalConfig(home, {
      ...globalConfig(),
      projectPolicies: { mode: "allowlisted", allowedRoots: [child] },
    });

    const resolved = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), child);
    expect(resolved.projectRoot).toBe(realpathSync(child));
    expect(resolved.sources.map((source) => source.path)).toEqual([join(child, "child.policy.json")]);

    writeFileSync(join(child, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: ["child.policy.mjs"] }));
    expect(() => resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), child)).toThrow(PolicyStartupError);
  });

  test("property: 1,024 canonical root aliases preserve exact allowlist selection", () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const project = join(root, "project");
    const alias = join(root, "project-alias");
    const cwd = join(project, "work");
    mkdirSync(join(project, ".safety-core"), { recursive: true });
    mkdirSync(cwd, { recursive: true });
    writeFileSync(join(project, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: [] }));
    symlinkSync(project, alias);

    for (let seed = 0; seed < 1_024; seed++) {
      writeGlobalConfig(home, {
        ...globalConfig(),
        projectPolicies: { mode: "allowlisted", allowedRoots: [seed % 2 === 0 ? project : alias] },
      });
      const resolved = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), cwd);
      expect(resolved.projectRoot, `seed ${seed}`).toBe(realpathSync(project));
    }
  });
});
