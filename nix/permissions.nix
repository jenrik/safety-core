# Home-manager module exposing safety-core's permission profiles as
# toggleable options. Each profile is a named, reusable group of permission
# rules that gets rendered into (or consulted at runtime by) the harnesses
# it targets -- currently Claude Code, OpenCode, and OpenCode2.
#
# This module only appends a PreToolUse hook entry pointing at the
# conventional `$HOME/.claude/hooks/gh_api_read_allow.mjs` path -- it relies
# on the consumer's existing Claude Code module to have already symlinked
# `pkgs.safety-core.claudeCodeHooks` (which now includes this hook
# automatically, since it's built from every non-underscore file under
# adapters/claude-code/) into that directory. Same for OpenCode
# and OpenCode2: their plugin wiring is untouched here, since
# adapters/opencode.ts's gh-api check ships as part of the existing,
# already-wired safety-core plugin file for both.
#
# Static profiles (readOnlyBash) are gated purely in Nix: their allow-list
# entries are present or absent depending on the option. Dynamic profiles
# (ghApiReadOnly) can't be expressed as static allow-list data, so their
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
  };

  config = mkMerge [
    {
      # Written unconditionally once the module is imported, with both keys
      # present regardless of which have a runtime consumer today -- a
      # future Pi permission engine can read this same file from day one.
      xdg.configFile."safety-core/profiles.json".text = builtins.toJSON {
        readOnlyBash = cfg.profiles.readOnlyBash.enable;
        ghApiReadOnly = cfg.profiles.ghApiReadOnly.enable;
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
      ];
    }

    (mkIf cfg.profiles.readOnlyBash.enable {
      programs.claude-code.settings.permissions.allow =
        map (cmd: "Bash(${cmd}:*)") readOnlyBashCommands;

      programs.opencode.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);

      # Coupled to nixos-config's private `modules.opencode2` option, not a
      # generic external home-manager module like `programs.opencode` --
      # acceptable only because nixos-config is safety-core's sole consumer
      # today (see flake.nix's homeManagerModules.default). Revisit if
      # safety-core ever gains a second consumer.
      modules.opencode2.settings.permission.bash =
        listToAttrs (map (cmd: nameValuePair "${cmd} *" "allow") readOnlyBashCommands);
    })
  ];
}
