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
        });

      overlays.default = final: _prev: {
        safety-core = final.callPackage ./package.nix { };
      };

      devShells = forAllSystems (system: {
        default = (pkgsFor system).mkShell {
          packages = [ (pkgsFor system).nodejs_22 ];
        };
      });
    };
}
