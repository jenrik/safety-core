import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as config from "../src/config.ts";

const defaults = {
  maxFunctionDepth: 128,
  maxNestedScriptDepth: 64,
  maxSteps: 25_000,
  maxWorkItems: 10_000,
};

function writeProfile(profile: unknown): string {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-config-"));
  const path = join(directory, "profiles.json");
  writeFileSync(path, JSON.stringify(profile));
  return path;
}

test("bash analysis configuration accepts only positive safe integer limits", () => {
  const loadBashAnalysisLimits = (config as Record<string, unknown>).loadBashAnalysisLimits as
    | ((path: string) => unknown)
    | undefined;

  expect(loadBashAnalysisLimits).toBeFunction();
  expect(loadBashAnalysisLimits!(writeProfile({
    bashAnalysis: {
      maxFunctionDepth: 7,
      maxNestedScriptDepth: -1,
      maxSteps: 1.5,
      maxWorkItems: Number.MAX_SAFE_INTEGER + 1,
    },
  }))).toEqual({
    maxFunctionDepth: 7,
    maxNestedScriptDepth: defaults.maxNestedScriptDepth,
    maxSteps: defaults.maxSteps,
    maxWorkItems: defaults.maxWorkItems,
  });
});

test("bash analysis configuration falls back to every safe default when absent or non-numeric", () => {
  const loadBashAnalysisLimits = (config as Record<string, unknown>).loadBashAnalysisLimits as
    | ((path: string) => unknown)
    | undefined;

  expect(loadBashAnalysisLimits).toBeFunction();
  expect(loadBashAnalysisLimits!(writeProfile({
    bashAnalysis: {
      maxFunctionDepth: "128",
      maxNestedScriptDepth: null,
      maxSteps: Number.POSITIVE_INFINITY,
      maxWorkItems: 0,
    },
  }))).toEqual(defaults);
  expect(loadBashAnalysisLimits!(writeProfile({}))).toEqual(defaults);
});

test("Nix renders all configured Bash analysis limits into the shared profile", () => {
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

test("Nix rejects every value outside the JavaScript positive-safe-integer domain", () => {
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

test("property: limit loading accepts exactly generated positive safe integers", () => {
  const loadBashAnalysisLimits = (config as Record<string, unknown>).loadBashAnalysisLimits as
    | ((path: string) => typeof defaults)
    | undefined;
  expect(loadBashAnalysisLimits).toBeFunction();

  let state = 0x4d595df4;
  for (let index = 0; index < 128; index++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const valid = state % 2 === 0;
    const value = valid ? (state % 10_000) + 1 : (state % 3 === 0 ? 0 : state + 0.5);
    const limits = loadBashAnalysisLimits!(writeProfile({ bashAnalysis: {
      maxFunctionDepth: value,
      maxNestedScriptDepth: value,
      maxSteps: value,
      maxWorkItems: value,
    } }));
    const expected = valid ? value : defaults.maxFunctionDepth;
    expect(limits.maxFunctionDepth).toBe(expected);
    expect(limits.maxNestedScriptDepth).toBe(valid ? value : defaults.maxNestedScriptDepth);
    expect(limits.maxSteps).toBe(valid ? value : defaults.maxSteps);
    expect(limits.maxWorkItems).toBe(valid ? value : defaults.maxWorkItems);
  }
});
