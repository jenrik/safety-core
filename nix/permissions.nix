# Home-manager module exposing safety-core's permission profiles as
# toggleable options. Each profile is a named, reusable group of permission
# rules that gets rendered into (or consulted at runtime by) the harnesses
# it targets -- currently Claude Code and OpenCode.
#
# This module only appends a PreToolUse hook entry pointing at the
# conventional `$HOME/.claude/hooks/gh_api_read_allow.mjs` path -- it relies
# on the consumer's existing Claude Code module to have already symlinked
# `pkgs.safety-core.claudeCodeHooks` (which now includes this hook
# automatically, since it's built from every non-underscore file under
# adapters/claude-code/) into that directory. Same for OpenCode: its plugin
# wiring is untouched here, since adapters/opencode.ts's gh-api check ships
# as part of the existing, already-wired safety-core plugin file.
#
# Static profiles (readOnlyBash) are gated purely in Nix: their allow-list
# entries are present or absent depending on the option. Dynamic profiles
# (ghApiReadOnly, ghReadOnly, helmReadOnly, ghPrCreate) can't be expressed as static allow-list data, so their
# hook/plugin code is wired in unconditionally once this module is imported,
# and their actual enabled/disabled state lives in one shared runtime file
# (~/.config/safety-core/profiles.json, see src/config.ts) that every
# harness adapter consults -- avoiding two independent Nix-rendered sources
# of truth for the same toggle.
{ config, lib, ... }:
with lib;
let
  cfg = config.programs.safetyCorePermissions;
  readOnlyBashCommands = builtins.fromJSON (builtins.readFile ../data/read-only-bash-commands.json);
in
{
  options.programs.safetyCorePermissions.profiles = {
    readOnlyBash.enable = mkEnableOption "auto-allow generic read-only bash commands (cat, tail, echo, ...)";
    ghApiReadOnly.enable = mkEnableOption "auto-allow verifiably read-only `gh api` calls";
    ghReadOnly.enable = mkEnableOption "auto-allow documented read-only `gh` subcommands through parsed command policy";
    helmReadOnly.enable = mkEnableOption "auto-allow documented read-only `helm` subcommands through parsed command policy";
    ghPrCreate = {
      enable = mkEnableOption "allow `gh pr create` only for explicitly allowlisted GitHub repositories or organizations; direct `gh api` calls are denied";
      allowedRepositories = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "owner/repository" "github.example.com/owner/repository" ];
        description = "Exact repositories where agents may create pull requests. Values use [HOST/]OWNER/REPO syntax; native commands must pass --repo HOST/OWNER/REPO explicitly.";
      };
      allowedOrganizations = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "owner" "github.example.com/owner" ];
        description = "Organizations where agents may create pull requests in any repository. Values use [HOST/]OWNER syntax; native commands must pass --repo HOST/OWNER/REPO explicitly.";
      };
    };
  };

  config = mkMerge [
    {
      # Written unconditionally once the module is imported, with both keys
      # present regardless of which have a runtime consumer today -- a
      # future Pi permission engine can read this same file from day one.
      xdg.configFile."safety-core/profiles.json".text = builtins.toJSON {
        readOnlyBash = cfg.profiles.readOnlyBash.enable;
        ghApiReadOnly = cfg.profiles.ghApiReadOnly.enable;
        ghReadOnly = cfg.profiles.ghReadOnly.enable;
        helmReadOnly = cfg.profiles.helmReadOnly.enable;
        ghPrCreate = {
          enabled = cfg.profiles.ghPrCreate.enable;
          allowedRepositories = cfg.profiles.ghPrCreate.allowedRepositories;
          allowedOrganizations = cfg.profiles.ghPrCreate.allowedOrganizations;
        };
      };

      # ghApiReadOnly's Claude Code hook entry: wired in unconditionally
      # (see module comment above); its behaviour is controlled by
      # profiles.json, read by adapters/claude-code/gh_api_read_allow.ts at
      # invocation time.
      programs.claude-code.settings.hooks.PreToolUse = mkAfter [
        {
          matcher = "Bash";
          hooks = [
            {
              type = "command";
              command = "$HOME/.claude/hooks/gh_api_read_allow.mjs";
            }
          ];
        }
        {
          matcher = "Bash";
          hooks = [
            {
              type = "command";
              command = "$HOME/.claude/hooks/read_only_cli_allow.mjs";
            }
          ];
        }
        {
          matcher = "Bash";
          hooks = [
            {
              type = "command";
              command = "$HOME/.claude/hooks/gh_pr_create_policy.mjs";
            }
          ];
        }
      ];
    }

    (mkIf cfg.profiles.readOnlyBash.enable {
      programs.claude-code.settings.permissions.allow =
        map (cmd: "Bash(${cmd}:*)") readOnlyBashCommands;

      programs.opencode.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);
    })
  ];
}
