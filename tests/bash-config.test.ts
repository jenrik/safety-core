import { expect, test } from "bun:test";
import { mkdtempSync, renameSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as config from "../src/config.ts";
import * as core from "../src/index.ts";

const defaults = {
  maxFunctionDepth: 128,
  maxNestedScriptDepth: 64,
  maxSteps: 7_500,
  maxWorkItems: 10_000,
};
const nixEvaluationTest = process.env.SAFETY_CORE_PACKAGED_TESTS === "1" ? test.skip : test;

function writeProfile(profile: unknown): string {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-config-"));
  const path = join(directory, "profiles.json");
  writeFileSync(path, JSON.stringify(profile));
  return path;
}

test("configured Bash snapshots are immutable and reject a malformed recognized field", () => {
  const loadBashProfileSnapshot = (config as Record<string, unknown>).loadBashProfileSnapshot as
    | ((path: string) => Record<string, unknown>)
    | undefined;
  expect(loadBashProfileSnapshot).toBeFunction();

  const snapshot = loadBashProfileSnapshot!(writeProfile({
    readOnlyBash: true,
    ghReadOnly: "true",
    dockerReadOnly: true,
    ghPrCreate: { enabled: true, allowedRepositories: ["acme/widgets", 4], allowedOrganizations: "acme" },
  }));
  expect(snapshot).toMatchObject({
    readOnlyBash: false,
    ghReadOnly: false,
    ghPrCreate: { enabled: false, allowedRepositories: [], allowedOrganizations: [] },
    strictProfiles: { dockerReadOnly: false },
  });
  expect(Object.isFrozen(snapshot)).toBe(true);
  expect(Object.isFrozen(snapshot.strictProfiles)).toBe(true);
  expect(Object.isFrozen(snapshot.ghPrCreate)).toBe(true);
});

test("configured Bash snapshots reject unknown root and nested configuration keys", () => {
  const loadBashProfileSnapshot = (config as Record<string, unknown>).loadBashProfileSnapshot as
    | ((path: string) => { readonly ghReadOnly: boolean })
    | undefined;
  expect(loadBashProfileSnapshot).toBeFunction();
  for (const profile of [
    { ghReadOnly: true, unknown: true },
    { ghReadOnly: true, ghPrCreate: { unknown: true } },
    { ghReadOnly: true, bashAnalysis: { unknown: 1 } },
  ]) expect(loadBashProfileSnapshot!(writeProfile(profile)).ghReadOnly).toBe(false);
});

test("profile snapshot sources atomically replace immutable generations", () => {
  const createBashProfileSnapshotSource = (config as Record<string, unknown>).createBashProfileSnapshotSource as
    | ((path: string) => { current(): { generation: number; snapshot: { ghReadOnly: boolean } }; reloadIfChanged(): { generation: number; snapshot: { ghReadOnly: boolean } } })
    | undefined;
  expect(createBashProfileSnapshotSource).toBeFunction();
  const path = writeProfile({ ghReadOnly: true });
  const source = createBashProfileSnapshotSource!(path);
  const first = source.current();
  expect(first.snapshot.ghReadOnly).toBe(true);
  expect(source.reloadIfChanged()).toBe(first);
  writeFileSync(path, JSON.stringify({ ghReadOnly: false }));
  const second = source.reloadIfChanged();
  expect(second.generation).toBeGreaterThan(first.generation);
  expect(second.snapshot.ghReadOnly).toBe(false);
  writeFileSync(path, JSON.stringify({ ghReadOnly: "true" }));
  expect(source.reloadIfChanged().snapshot.ghReadOnly).toBe(false);
});

test("profile sources follow a Home Manager-style symlink retarget", () => {
  const createBashProfileSnapshotSource = (config as Record<string, unknown>).createBashProfileSnapshotSource as
    | ((path: string) => { current(): { generation: number; snapshot: { ghReadOnly: boolean } }; reloadIfChanged(): { generation: number; snapshot: { ghReadOnly: boolean } } })
    | undefined;
  expect(createBashProfileSnapshotSource).toBeFunction();
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-config-link-"));
  const first = join(directory, "first.json");
  const second = join(directory, "second.json");
  const current = join(directory, "profiles.json");
  writeFileSync(first, JSON.stringify({ ghReadOnly: true }));
  writeFileSync(second, JSON.stringify({ ghReadOnly: false }));
  symlinkSync(first, current);
  const source = createBashProfileSnapshotSource!(current);
  expect(source.current().snapshot.ghReadOnly).toBe(true);
  // Replacing the pathname, rather than its realpath target, mirrors activation.
  const replacement = join(directory, "replacement");
  symlinkSync(second, replacement);
  renameSync(replacement, current);
  expect(source.reloadIfChanged().snapshot.ghReadOnly).toBe(false);
});

nixEvaluationTest("Nix renders all configured Bash analysis limits into the shared profile", () => {
  const root = process.cwd();
  const profile = JSON.parse(execFileSync("nix", [
    "eval", "--impure", "--json", "--expr", `
      let
        flake = builtins.getFlake ${JSON.stringify(root)};
        lib = flake.inputs.nixpkgs.lib;
        stub = { lib, ... }: {
          options = {
            xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
            programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
            programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
          };
        };
        evaluated = lib.evalModules {
          modules = [
            stub
            ${root}/nix/permissions.nix
            {
              config.programs.safetyCorePermissions.bashAnalysis = {
                maxFunctionDepth = 7;
                maxNestedScriptDepth = 6;
                maxSteps = 5;
                maxWorkItems = 4;
              };
            }
          ];
        };
      in builtins.fromJSON evaluated.config.xdg.configFile."safety-core/profiles.json".text
    `,
  ], { encoding: "utf8" }));

  expect(profile.bashAnalysis).toEqual({
    maxFunctionDepth: 7,
    maxNestedScriptDepth: 6,
    maxSteps: 5,
    maxWorkItems: 4,
  });
});

nixEvaluationTest("Nix rejects every value outside the JavaScript positive-safe-integer domain", () => {
  const root = process.cwd();
  for (const field of ["maxFunctionDepth", "maxNestedScriptDepth", "maxSteps", "maxWorkItems"]) {
    for (const value of [0, -1, Number.MAX_SAFE_INTEGER + 1]) {
    expect(() => execFileSync("nix", [
      "eval", "--impure", "--expr", `
        let
          flake = builtins.getFlake ${JSON.stringify(root)};
          lib = flake.inputs.nixpkgs.lib;
          stub = { lib, ... }: {
            options = {
              xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
              programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
              programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
            };
          };
        in (lib.evalModules { modules = [ stub ${root}/nix/permissions.nix {
          config.programs.safetyCorePermissions.bashAnalysis.${field} = ${value};
        } ]; }).config.programs.safetyCorePermissions.bashAnalysis.${field}
      `,
    ], { encoding: "utf8", stdio: "pipe" })).toThrow();
    }
  }
});

test("property: only literal true enables generated profile values", () => {
  const loadBashProfileSnapshot = (config as Record<string, unknown>).loadBashProfileSnapshot as
    | ((path: string) => { readonly ghReadOnly: boolean })
    | undefined;
  expect(loadBashProfileSnapshot).toBeFunction();
  const values: unknown[] = [true, false, 1, 0, "true", null, [], {}, undefined];
  for (const value of values) {
    expect(loadBashProfileSnapshot!(writeProfile({ ghReadOnly: value })).ghReadOnly, String(value)).toBe(value === true);
  }
});

test("public core exports only structured Bash evaluation APIs", () => {
  for (const retired of [
    "parseBash", "parseBashForSecretRead", "checkBashForGithub", "analyzeKubectl",
    "checkBashForKubectlSecret", "summariseKubectlSecret", "analyzeGhApiCommand",
    "analyzeGhPrCreateCommand", "analyzeStrictReadOnlyCommand", "mapOpenCodeBashStatus",
    "evaluateBashPermission", "mapBashPermissionStatus", "shouldBlockPiBash",
    "mapClaudeBashDecision", "loadProfileConfig", "analyzeHelmReadOnlyCommand",
  ]) expect(retired in core, retired).toBe(false);
  expect(core.parseBashProgram).toBeFunction();
  expect(core.evaluateBashGuards).toBeFunction();
  expect(core.evaluateConfiguredBash).toBeFunction();
});
