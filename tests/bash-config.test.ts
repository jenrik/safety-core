import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";

import * as config from "../src/config.ts";

test("the public config boundary is the strict authoritative global config", () => {
  expect(config.loadGlobalPolicyConfig).toBeFunction();
  expect("loadBashProfileSnapshot" in config).toBe(false);
  expect("createBashProfileSnapshotSource" in config).toBe(false);
});

test("Nix renders the same complete authoritative config shape", () => {
  const root = process.cwd();
  const rendered = JSON.parse(execFileSync("nix", ["eval", "--impure", "--json", "--expr", `
    let
      flake = builtins.getFlake ${JSON.stringify(root)};
      lib = flake.inputs.nixpkgs.lib;
      stub = { lib, ... }: { options = {
        xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
        programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
      }; };
      evaluated = lib.evalModules { specialArgs = { pkgs = flake.inputs.nixpkgs.legacyPackages.x86_64-linux; }; modules = [ stub ${root}/nix/permissions.nix {
        config.programs.safetyCorePermissions.completePolicySources = true;
        config.programs.safetyCorePermissions.bashAnalysis.maxSteps = 5;
      } ]; };
    in builtins.fromJSON (builtins.unsafeDiscardStringContext evaluated.config.xdg.configFile."safety-core/config.json".text)
  `], { encoding: "utf8" }));
  expect(rendered).toMatchObject({ version: 1, projectPolicies: { mode: "disabled" }, bashAnalysis: { maxSteps: 5 } });
  expect(rendered.policies).toHaveLength(9);
});
