{
  description = "Shared TS safety-policy core for pi/opencode/claude-code coding-agent hooks";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      packages = forAllSystems (system:
        let sc = (pkgsFor system).callPackage ./package.nix { };
        in {
          # opencodePluginFile is a string (a path inside opencodeDir), not a
          # derivation, so it can't be listed here — it's only available
          # through overlays.default's attrset below.
          inherit (sc) piExtensionDir claudeCodeHooks;
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sc = pkgs.callPackage ./package.nix { };
        in {
          hooks-runtime = pkgs.runCommand "safety-core-hooks-runtime-check" { } ''
            set -e
            payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat /etc/kubernetes/secret.pem"}}'

            set +e
            echo "$payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/secrets_policy.mjs
            code=$?
            set -e

            if [ "$code" -ne 2 ]; then
              echo "expected secrets_policy.mjs to exit 2 (block) for a dangerous command, got $code" >&2
              exit 1
            fi

            touch $out
          '';

          gh-api-hook-runtime = pkgs.runCommand "safety-core-gh-api-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"ghApiReadOnly":true}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

            allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api user"}}'
            deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api -f title=x repos/o/r/issues"}}'

            # gh_api_read_allow.mjs uses emitAllow/emitDeny (PreToolUse
            # override), which both exit 0 and write a permissionDecision
            # JSON to stdout -- unlike secrets_policy.mjs's hardBlock (exit
            # 2). Assert on stdout content, not exit code.
            allow_out=$(echo "$allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_api_read_allow.mjs)
            deny_out=$(echo "$deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_api_read_allow.mjs)

            if ! echo "$allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected gh_api_read_allow.mjs to allow a read-only call, got: $allow_out" >&2
              exit 1
            fi
            if ! echo "$deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected gh_api_read_allow.mjs to deny a -f-parameterised call with no explicit --method, got: $deny_out" >&2
              exit 1
            fi

            touch $out
          '';

          gh-api-hook-safety-core-config-home-override = pkgs.runCommand "safety-core-gh-api-hook-config-home-override-check" { } ''
            set -e

            # SAFETY_CORE_CONFIG_HOME must win over XDG_CONFIG_HOME, simulating a
            # harness (OpenCode2) that overrides XDG_CONFIG_HOME for its own config
            # isolation but still needs safety-core's shared profile toggle to work.
            mkdir -p override-config/safety-core decoy-config/safety-core
            echo '{"ghApiReadOnly":true}' > override-config/safety-core/profiles.json
            echo '{"ghApiReadOnly":false}' > decoy-config/safety-core/profiles.json

            export SAFETY_CORE_CONFIG_HOME="$PWD/override-config"
            export XDG_CONFIG_HOME="$PWD/decoy-config"

            allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api user"}}'
            allow_out=$(echo "$allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_api_read_allow.mjs)

            if ! echo "$allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected SAFETY_CORE_CONFIG_HOME to take precedence over XDG_CONFIG_HOME, got: $allow_out" >&2
              exit 1
            fi

            touch $out
          '';
        });

      overlays.default = final: _prev: {
        safety-core = final.callPackage ./package.nix { };
      };

      homeManagerModules.default = import ./nix/permissions.nix;

      devShells = forAllSystems (system: {
        default = (pkgsFor system).mkShell {
          packages = [ (pkgsFor system).nodejs_22 ];
        };
      });
    };
}
