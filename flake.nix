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
          lib = pkgs.lib;
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

          command-profile-tests = pkgs.runCommand "safety-core-command-profile-tests"
            {
              nativeBuildInputs = [ pkgs.bun ];
            } ''
            set -e
            mkdir test-work
            cp -r ${builtins.dirOf sc.opencodePluginFile}/src test-work/src
            cp -r ${builtins.dirOf sc.opencodePluginFile}/data test-work/data
            cp -r ${builtins.dirOf sc.opencodePluginFile}/node_modules test-work/node_modules
            cp ${builtins.dirOf sc.opencodePluginFile}/tree-sitter-bash.wasm test-work/
            cp -r ${./adapters} test-work/adapters
            cp -r ${./tests} test-work/tests
            cd test-work
            bun test tests/gh-pr-create-parser-failure.test.ts
            bun test tests/gh-pr-create.test.ts
            bun test tests/read-only-cli.test.ts
            bun test tests/opencode-read-only-cli.test.ts
            touch $out
          '';

          gh-pr-create-hook-runtime = pkgs.runCommand "safety-core-gh-pr-create-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"ghApiReadOnly":true,"ghPrCreate":{"enabled":true,"allowedRepositories":["acme/widgets"],"allowedOrganizations":[]}}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

            allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --repo github.com/acme/widgets --fill"}}'
            deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh alias set create-pr \"pr create --repo github.com/attacker/widgets\""}}'
            compound_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --repo github.com/acme/widgets --fill; gh api user"}}'

            allow_out=$(echo "$allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_pr_create_policy.mjs)
            deny_out=$(echo "$deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_pr_create_policy.mjs)
            compound_out=$(echo "$compound_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_pr_create_policy.mjs)
            gh_api_compound_out=$(echo "$compound_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/gh_api_read_allow.mjs)

            if ! echo "$allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected gh_pr_create_policy.mjs to allow an allowlisted PR, got: $allow_out" >&2
              exit 1
            fi
            if ! echo "$deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected gh_pr_create_policy.mjs to deny a non-allowlisted PR, got: $deny_out" >&2
              exit 1
            fi
            if ! echo "$compound_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected compound Bash invocation to be denied, got: $compound_out" >&2
              exit 1
            fi
            if ! echo "$gh_api_compound_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected gh-api profile not to override a compound PR denial, got: $gh_api_compound_out" >&2
              exit 1
            fi

            touch $out
          '';

          read-only-cli-hook-runtime = pkgs.runCommand "safety-core-read-only-cli-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"ghReadOnly":true,"helmReadOnly":true}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

            gh_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh issue list"}}'
            gh_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh issue list; id"}}'
            helm_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"helm list"}}'

            gh_allow_out=$(echo "$gh_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/read_only_cli_allow.mjs)
            gh_defer_out=$(echo "$gh_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/read_only_cli_allow.mjs)
            helm_allow_out=$(echo "$helm_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/read_only_cli_allow.mjs)

            if ! echo "$gh_allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected read_only_cli_allow.mjs to allow gh issue list, got: $gh_allow_out" >&2
              exit 1
            fi
            if [ -n "$gh_defer_out" ]; then
              echo "expected read_only_cli_allow.mjs to defer a compound command, got: $gh_defer_out" >&2
              exit 1
            fi
            if ! echo "$helm_allow_out" | grep -q '"permissionDecision":"allow"'; then
              echo "expected read_only_cli_allow.mjs to allow helm list, got: $helm_allow_out" >&2
              exit 1
            fi

            touch $out
          '';

          opencode-plugin-loads = pkgs.runCommand "safety-core-opencode-plugin-loads-check"
            {
              nativeBuildInputs = [ pkgs.bun ];
            } ''
            set -e
            cat > check.ts <<'EOF'
            const path = process.argv[2];
            const mod = await import(path);
            if (typeof mod.default !== "function") {
              console.error(`expected default export of ''${path} to be a function, got ''${typeof mod.default}`);
              process.exit(1);
            }
            const hooks = await mod.default({});
            const required = ["tool.execute.before", "permission.ask", "tool.execute.after"];
            for (const name of required) {
              if (typeof hooks[name] !== "function") {
                console.error(`expected hook "''${name}" to be a function, got ''${typeof hooks[name]}`);
                process.exit(1);
              }
            }
            EOF

            bun run check.ts ${sc.opencodePluginFile}
            touch $out
          '';

          readonly-bash-opencode-eval =
            let
              stub = { lib, ... }: {
                options = {
                  xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
                  programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                  programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                };
              };
              evaled = lib.evalModules {
                modules = [
                  stub
                  ./nix/permissions.nix
                  { config.programs.safetyCorePermissions.profiles.readOnlyBash.enable = true; }
                ];
              };
              bashAllow = evaled.config.programs.opencode.settings.permission.bash;
            in
            assert bashAllow ? "cat *";
            assert bashAllow."cat *" == "allow";
            pkgs.runCommand "safety-core-readonlybash-opencode-eval-check" { } "touch $out";

          gh-pr-create-profile-eval =
            let
              stub = { lib, ... }: {
                options = {
                  xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
                  programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                  programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                };
              };
              evaled = lib.evalModules {
                modules = [
                  stub
                  ./nix/permissions.nix
                  {
                    config.programs.safetyCorePermissions.profiles.ghPrCreate = {
                      enable = true;
                      allowedRepositories = [ "acme/widgets" ];
                      allowedOrganizations = [ "trusted-org" ];
                    };
                  }
                ];
              };
              profile = builtins.fromJSON evaled.config.xdg.configFile."safety-core/profiles.json".text;
            in
            assert profile.ghPrCreate.enabled;
            assert profile.ghPrCreate.allowedRepositories == [ "acme/widgets" ];
            assert profile.ghPrCreate.allowedOrganizations == [ "trusted-org" ];
            pkgs.runCommand "safety-core-gh-pr-create-profile-eval-check" { } "touch $out";

          read-only-cli-profile-eval =
            let
              stub = { lib, ... }: {
                options = {
                  xdg.configFile = lib.mkOption { type = lib.types.attrsOf lib.types.anything; default = { }; };
                  programs.claude-code.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                  programs.opencode.settings = lib.mkOption { type = lib.types.anything; default = { }; };
                };
              };
              evaled = lib.evalModules {
                modules = [
                  stub
                  ./nix/permissions.nix
                  {
                    config.programs.safetyCorePermissions.profiles.ghReadOnly.enable = true;
                    config.programs.safetyCorePermissions.profiles.helmReadOnly.enable = true;
                  }
                ];
              };
              profile = builtins.fromJSON evaled.config.xdg.configFile."safety-core/profiles.json".text;
            in
            assert profile.ghReadOnly;
            assert profile.helmReadOnly;
            pkgs.runCommand "safety-core-read-only-cli-profile-eval-check" { } "touch $out";
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
