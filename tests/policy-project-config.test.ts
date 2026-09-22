import { describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PolicyStartupError, loadGlobalPolicyConfig, resolveSessionPolicyConfig } from "../src/policy/config.ts";
import { evaluatePolicyEvents } from "../src/policy/evaluate.ts";
import { loadPolicySet } from "../src/policy/load.ts";
import { loadPolicyRuntime, policyRuntimeManifest } from "../src/policy/runtime.ts";
import type { InvocationView } from "../src/policy/types.ts";

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };

function fixtureDirectory(): string {
  return mkdtempSync(join(tmpdir(), "safety-core-project-policy-"));
}

function writeGlobalConfig(home: string, mode: "disabled" | "allowlisted" | "all", policies: readonly string[] = [], allowedRoots: readonly string[] = []): string {
  const directory = join(home, "safety-core");
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "config.json");
  writeFileSync(path, JSON.stringify({
    version: 1,
    policies,
    projectPolicies: mode === "allowlisted" ? { mode, allowedRoots } : { mode },
    bashAnalysis: limits,
  }));
  return path;
}

function writeProjectConfig(root: string, policies: readonly string[]): string {
  const directory = join(root, ".safety-core");
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "config.json");
  writeFileSync(path, JSON.stringify({ version: 1, policies }));
  return path;
}

function writeDslPolicy(path: string, layer: "guard" | "permission", decision: "allow" | "deny" | "ignore"): void {
  writeFileSync(path, JSON.stringify({
    language: "safety-core/bash-policy-v1",
    layer,
    select: [{ kind: "invocation" }],
    registers: {},
    start: "start",
    states: {
      start: {
        cases: [],
        default: { decision: "ignore" },
        end: decision === "ignore" ? { decision } : { decision, reason: [decision] },
      },
    },
  }));
}

function invocation(): InvocationView {
  return {
    kind: "invocation",
    executable: { kind: "known", value: "tool" },
    executableIdentity: { qualification: "incomplete", spelling: "tool", basename: "tool", chain: [], failure: { kind: "not-found" } },
    argv: [],
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  };
}

describe("globally gated project DSL policies", () => {
  test("does not inspect candidates while disabled and selects only the nearest trusted root", () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const parent = join(root, "parent");
    const project = join(parent, "project");
    const cwd = join(project, "nested", "cwd");
    mkdirSync(cwd, { recursive: true });
    writeProjectConfig(parent, ["parent.policy.json"]);
    writeProjectConfig(project, ["project.policy.json"]);
    writeGlobalConfig(home, "disabled");

    expect(resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), cwd).projectRoot).toBeUndefined();

    writeGlobalConfig(home, "allowlisted", [], [project]);
    const selected = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), cwd);
    expect(selected.projectRoot).toBe(realpathSync(project));
    expect(selected.sources).toEqual([{ path: join(project, "project.policy.json"), scope: "project" }]);

    writeGlobalConfig(home, "allowlisted", [], [parent]);
    expect(resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), cwd).projectRoot).toBeUndefined();
  });

  test("resolves relative and absolute project DSL references but rejects every other project source and schema field", () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const project = join(root, "project");
    const external = join(root, "external.policy.json");
    mkdirSync(project, { recursive: true });
    writeGlobalConfig(home, "all");
    const configPath = writeProjectConfig(project, ["policies/local.policy.json", external]);

    const selected = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), project);
    expect(selected.sources).toEqual([
      { path: join(project, "policies", "local.policy.json"), scope: "project" },
      { path: external, scope: "project" },
    ]);

    for (const invalid of [
      { version: 1, policies: ["code.policy.mjs"] },
      { version: 1, policies: ["not-a-policy.json.bak"] },
      { version: 1, policies: [], unknown: true },
      { version: 2, policies: [] },
      { version: 1, policies: "not-an-array" },
    ]) {
      writeFileSync(configPath, JSON.stringify(invalid));
      expect(() => resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), project), JSON.stringify(invalid))
        .toThrow(PolicyStartupError);
    }
  });

  test("property: 1,024 canonical aliases accept only the exact nearest allowlisted root", () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const allowed = join(root, "allowed");
    const denied = join(root, "denied");
    const allowedAlias = join(root, "allowed-alias");
    const deniedAlias = join(root, "denied-alias");
    mkdirSync(join(allowed, "work"), { recursive: true });
    mkdirSync(join(denied, "work"), { recursive: true });
    writeProjectConfig(allowed, []);
    writeProjectConfig(denied, []);
    symlinkSync(allowed, allowedAlias);
    symlinkSync(denied, deniedAlias);

    for (let seed = 0; seed < 1_024; seed++) {
      const project = seed % 2 === 0 ? allowed : denied;
      const configuredRoot = seed % 4 < 2 ? allowed : allowedAlias;
      writeGlobalConfig(home, "allowlisted", [], [configuredRoot]);
      const selected = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), join(project, "work"));
      expect(selected.projectRoot, `seed ${seed}`).toBe(project === allowed ? realpathSync(allowed) : undefined);
    }
  });

  test("rejects a project JSON-suffixed alias to an already-global code source", async () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const project = join(root, "project");
    const codePolicy = join(root, "global.policy.mjs");
    const projectAlias = join(project, "alias.policy.json");
    mkdirSync(project, { recursive: true });
    writeFileSync(codePolicy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
    symlinkSync(codePolicy, projectAlias);
    writeGlobalConfig(home, "all", [codePolicy]);
    writeProjectConfig(project, ["alias.policy.json"]);

    const resolved = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), project);
    await expect(loadPolicySet(resolved)).rejects.toThrow("only in global configuration");
  });

  test("loads one canonical additive set, lets project permissions expand coverage, and retains global deny dominance", async () => {
    const root = fixtureDirectory();
    const home = join(root, "home");
    const project = join(root, "project");
    const globalDeny = join(root, "global-deny.policy.json");
    const globalAllow = join(root, "global-allow.policy.json");
    const globalAllowAlias = join(root, "global-allow-alias.policy.json");
    const projectAllow = join(project, "project-allow.policy.json");
    mkdirSync(project, { recursive: true });
    writeDslPolicy(globalDeny, "guard", "deny");
    writeDslPolicy(globalAllow, "permission", "allow");
    writeDslPolicy(projectAllow, "permission", "allow");
    symlinkSync(globalAllow, globalAllowAlias);
    writeGlobalConfig(home, "all", [globalDeny, globalAllowAlias]);
    writeProjectConfig(project, ["project-allow.policy.json", globalAllow]);

    const resolved = resolveSessionPolicyConfig(loadGlobalPolicyConfig({ SAFETY_CORE_CONFIG_HOME: home }), project);
    const loaded = await loadPolicySet(resolved);
    expect(loaded.sources.map((source) => source.canonicalPath)).toEqual([
      realpathSync(globalDeny), realpathSync(globalAllow), realpathSync(projectAllow),
    ]);
    expect(evaluatePolicyEvents([invocation()], loaded.policies, { complete: true }).decision).toBe("deny");

    writeGlobalConfig(home, "all", []);
    const runtime = await loadPolicyRuntime(project, { SAFETY_CORE_CONFIG_HOME: home });
    expect(evaluatePolicyEvents([invocation()], runtime.policySet.policies, { complete: true }).decision).toBe("allow");
    const manifest = policyRuntimeManifest(runtime, project);
    expect(manifest.projectRoot).toBe(realpathSync(project));
    expect(manifest.configurations.map((source) => source.canonicalPath)).toEqual([
      realpathSync(join(home, "safety-core", "config.json")),
      realpathSync(join(project, ".safety-core", "config.json")),
    ]);
    expect(manifest.configurations.every((source) => /^[a-f0-9]{64}$/.test(source.sha256))).toBeTrue();
    expect(manifest.sources.every((source) => /^[a-f0-9]{64}$/.test(source.sha256))).toBeTrue();
  });
});
