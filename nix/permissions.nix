{ config, lib, pkgs, ... }:
with lib;
let
  cfg = config.programs.safetyCorePermissions;
  safetyCore = pkgs.safety-core or (pkgs.callPackage ../package.nix { });
  completeSources = [
    safetyCore.dslPolicies.secretRead
    safetyCore.dslPolicies.githubHttp
    safetyCore.dslPolicies.kubectl
    safetyCore.dslPolicies.unsupportedShellSource
    safetyCore.dslPolicies.genericReadOnly
    safetyCore.dslPolicies.ghReadOnly
    safetyCore.dslPolicies.helmReadOnly
    safetyCore.dslPolicies.ghApi
  ] ++ safetyCore.dslPolicies.strictReadOnly;
  prSource = safetyCore.mkGhPrCreateDslPolicy {
    allowedRepositories = cfg.prCreate.allowedRepositories;
    allowedOrganizations = cfg.prCreate.allowedOrganizations;
  };
  sources = cfg.policySources
    ++ (if cfg.completePolicySources then completeSources else [ ])
    ++ optional cfg.prCreate.enable prSource;
in {
  options.programs.safetyCorePermissions = {
    policySources = mkOption {
      type = types.listOf types.path;
      default = [ ];
      description = "Authoritative global trusted Bash policy source paths.";
    };
    completePolicySources = mkEnableOption "the complete built-in trusted policy source set";
    prCreate = {
      enable = mkEnableOption "generate and add a repository-scoped gh pr create DSL policy source";
      allowedRepositories = mkOption { type = types.listOf types.str; default = [ ]; };
      allowedOrganizations = mkOption { type = types.listOf types.str; default = [ ]; };
    };
    projectPolicies = {
      mode = mkOption { type = types.enum [ "disabled" "allowlisted" "all" ]; default = "disabled"; };
      allowedRoots = mkOption { type = types.listOf types.path; default = [ ]; };
    };
    bashAnalysis = {
      maxFunctionDepth = mkOption { type = types.addCheck types.ints.positive (value: value <= 9007199254740991); default = 128; };
      maxNestedScriptDepth = mkOption { type = types.addCheck types.ints.positive (value: value <= 9007199254740991); default = 64; };
      maxSteps = mkOption { type = types.addCheck types.ints.positive (value: value <= 9007199254740991); default = 7500; };
      maxWorkItems = mkOption { type = types.addCheck types.ints.positive (value: value <= 9007199254740991); default = 10000; };
    };
  };

  config = {
    xdg.configFile."safety-core/config.json".text = builtins.toJSON {
      version = 1;
      policies = map toString sources;
      projectPolicies = if cfg.projectPolicies.mode == "allowlisted" then {
        mode = "allowlisted";
        allowedRoots = map toString cfg.projectPolicies.allowedRoots;
      } else { mode = cfg.projectPolicies.mode; };
      bashAnalysis = cfg.bashAnalysis;
    };
    programs.claude-code.settings.hooks.PreToolUse = mkAfter [{
      matcher = "Bash";
      hooks = [{ type = "command"; command = "$HOME/.claude/hooks/bash_policy.mjs"; }];
    }];
  };
}
