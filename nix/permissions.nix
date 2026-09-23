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
      description = "Authoritative global policy sources written as config.json policies.";
    };
    completePolicySources = mkEnableOption "the complete packaged DSL policy source set";
    installCli = mkEnableOption "install the packaged safety-core CLI";
    installClaudeBashHook = mkEnableOption "install the packaged immutable-session Claude Bash hook";
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
    xdg.configFile."safety-core/bin/safety-core" = mkIf cfg.installCli {
      source = "${safetyCore.safetyCoreCli}/bin/safety-core";
      executable = true;
    };
    xdg.configFile."safety-core/claude/bash_policy.mjs" = mkIf cfg.installClaudeBashHook {
      source = "${safetyCore.claudeCodeHooks}/bash_policy.mjs";
      executable = true;
    };
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
      hooks = [{ type = "command"; command = "\${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs"; }];
    }];
    programs.claude-code.settings.hooks.SessionStart = mkAfter [{
      hooks = [{ type = "command"; command = "\${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs"; }];
    }];
  };
}
