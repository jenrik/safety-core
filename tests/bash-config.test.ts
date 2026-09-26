import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";

import * as config from "../src/config.ts";

function evaluateNix(overrides: string) {
  const root = process.cwd();
  return JSON.parse(execFileSync("nix", ["eval", "--impure", "--json", "--expr", `
    let
      flake = builtins.getFlake ${JSON.stringify(root)};
      lib = flake.inputs.nixpkgs.lib;
      stub = { lib, ... }: { options = {
        home.packages = lib.mkOption { type = lib.types.listOf lib.types.package; default = [ ]; };
        xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
        programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
      }; };
      evaluated = lib.evalModules { specialArgs = { pkgs = flake.inputs.nixpkgs.legacyPackages.x86_64-linux; }; modules = [ stub ${root}/nix/permissions.nix {
        ${overrides}
      } ]; };
      files = evaluated.config.xdg.configFile;
    in {
      config = builtins.fromJSON (builtins.unsafeDiscardStringContext files."safety-core/config.json".text);
      cli = map toString evaluated.config.home.packages;
      claudeHookFile = if files ? "safety-core/claude/bash_policy.mjs" then toString files."safety-core/claude/bash_policy.mjs".source else null;
      hooks = evaluated.config.programs.claude-code.settings.hooks or { };
    }
  `], { encoding: "utf8" }));
}

test("the public config boundary is the strict authoritative global config", () => {
  expect(config.loadGlobalPolicyConfig).toBeFunction();
  expect("loadBashProfileSnapshot" in config).toBe(false);
  expect("createBashProfileSnapshotSource" in config).toBe(false);
});

test("Nix renders the same complete authoritative config shape", () => {
  const rendered = evaluateNix(`
    config.programs.safetyCorePermissions.completePolicySources = true;
    config.programs.safetyCorePermissions.bashAnalysis.maxSteps = 5;
  `).config;
  expect(rendered).toMatchObject({ version: 1, projectPolicies: { mode: "disabled" }, bashAnalysis: { maxSteps: 5 }, pi: { autoApprove: false } });
  expect(rendered.policies).toHaveLength(27);
});

test("Nix renders configured Pi permissive and judge defaults", () => {
  const rendered = evaluateNix(`
    config.programs.safetyCorePermissions.pi.autoApprove = true;
    config.programs.safetyCorePermissions.pi.judgeModel = "anthropic/claude-haiku";
  `).config;
  expect(rendered.pi).toEqual({ autoApprove: true, judgeModel: "anthropic/claude-haiku" });
});

test("Nix installs the CLI on PATH and registers Claude hooks only when enabled", () => {
  const disabled = evaluateNix("");
  expect(disabled.cli).toEqual([]);
  expect(disabled.claudeHookFile).toBeNull();
  expect(disabled.hooks).toEqual({});

  const enabled = evaluateNix(`
    config.programs.safetyCorePermissions.installCli = true;
    config.programs.safetyCorePermissions.installClaudeBashHook = true;
  `);
  expect(enabled.cli).toHaveLength(1);
  expect(enabled.cli[0]).toContain("safety-core");
  expect(enabled.claudeHookFile).toContain("claude-code-safety-hooks");
  expect(enabled.hooks).toEqual({
    PreToolUse: [{
      matcher: "Bash",
      hooks: [{ type: "command", command: "${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs" }],
    }],
    SessionStart: [{
      hooks: [{ type: "command", command: "${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs" }],
    }],
  });
}, 15_000);
