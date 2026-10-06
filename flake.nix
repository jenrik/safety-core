{
  description = "Shared TS safety-policy core for pi/opencode/claude-code coding-agent hooks";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      scFor = system: (pkgsFor system).callPackage ./package.nix { };
    in
    {
      packages = forAllSystems (
        system:
        let
          sc = scFor system;
        in
        {
          inherit (sc)
            piExtensionDir
            opencodePlugin
            opencodeV2Plugin
            opencodeTuiPlugin
            claudeCodeHooks
            safetyCoreCli
            core
            policySources
            ;
          default = sc.core;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          sc = scFor system;
          prPolicy = sc.mkGhPrCreateDslPolicy {
            allowedRepositories = [ "acme/widgets" ];
            allowedOrganizations = [ ];
          };
          completePolicySources = sc.dslPolicies.all;
          productionDslPolicies = completePolicySources ++ [ "${prPolicy}/gh-pr-create.policy.json" ];
          evalPermissions =
            module:
            let
              stub = { lib, ... }: {
                options = {
                  home.packages = lib.mkOption {
                    type = lib.types.listOf lib.types.package;
                    default = [ ];
                  };
                  xdg.configFile = lib.mkOption {
                    type = lib.types.attrsOf lib.types.anything;
                    default = { };
                  };
                  programs.claude-code.settings = lib.mkOption {
                    type = lib.types.anything;
                    default = { };
                  };
                };
              };
              evaluated = lib.evalModules {
                specialArgs = { inherit pkgs; };
                modules = [
                  stub
                  ./nix/permissions.nix
                  module
                ];
              };
              files = evaluated.config.xdg.configFile;
            in
            {
              config = builtins.fromJSON (
                builtins.unsafeDiscardStringContext files."safety-core/config.json".text
              );
              cli = map toString evaluated.config.home.packages;
              claudeHookFile =
                if files ? "safety-core/claude/bash_policy.mjs" then
                  toString files."safety-core/claude/bash_policy.mjs".source
                else
                  null;
              hooks = evaluated.config.programs.claude-code.settings.hooks or { };
            };
          completeEval = evalPermissions {
            config.programs.safetyCorePermissions.completePolicySources = true;
            config.programs.safetyCorePermissions.bashAnalysis.maxSteps = 5;
          };
          piEval = evalPermissions {
            config.programs.safetyCorePermissions.pi.autoApprove = true;
            config.programs.safetyCorePermissions.pi.judgeModel = "anthropic/claude-haiku";
            config.programs.safetyCorePermissions.pi.showFullCommand = false;
          };
          disabledEval = evalPermissions { };
          enabledEval = evalPermissions {
            config.programs.safetyCorePermissions.installCli = true;
            config.programs.safetyCorePermissions.installClaudeBashHook = true;
          };
          expectedHooks = {
            PreToolUse = [
              {
                matcher = "Bash";
                hooks = [
                  {
                    type = "command";
                    command = "\${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs";
                  }
                ];
              }
            ];
            SessionStart = [
              {
                hooks = [
                  {
                    type = "command";
                    command = "\${XDG_CONFIG_HOME:-$HOME/.config}/safety-core/claude/bash_policy.mjs";
                  }
                ];
              }
            ];
          };
        in
        {
          code-policies-runtime = pkgs.runCommand "safety-core-code-policies-runtime-check" { } ''
            set -e
            ${pkgs.nodejs_22}/bin/node --input-type=module -e '
              const policy = (await import(process.argv[1])).default;
              if (!Object.isFrozen(policy) || policy.apiVersion !== 1 || typeof policy.evaluate !== "function") process.exit(1);
            ' ${sc.codePolicies.apiFixture}/api-fixture.policy.mjs
            touch $out
          '';
          dsl-policies-complete =
            pkgs.runCommand "safety-core-dsl-policies-complete-check"
              {
                buildInputs = [
                  pkgs.coreutils
                  pkgs.diffutils
                  pkgs.findutils
                ];
              }
              ''
                set -e
                for path in ${lib.concatStringsSep " " sc.dslPolicies.all}; do
                  echo "$path"
                done > "$TMPDIR/registered"
                find ${sc.policySources} -name '*.policy.json' | LC_ALL=C sort > "$TMPDIR/packaged"
                LC_ALL=C sort -o "$TMPDIR/registered" "$TMPDIR/registered"
                diff -u "$TMPDIR/registered" "$TMPDIR/packaged"
                test "$(wc -l < "$TMPDIR/registered")" -gt 0
                touch $out
              '';
          cli-loads = pkgs.runCommand "safety-core-cli-loads-check" { } ''
            set -e
            test -x ${sc.core}/bin/safety-core
            test -f ${sc.piExtensionDir}/index.ts
            test -f ${sc.opencodePlugin}/index.ts
            test -f ${sc.opencodeV2Plugin}/index.ts
            test -f ${sc.opencodeTuiPlugin}/index.ts
            grep -q '@safety-core/core' ${sc.piExtensionDir}/index.ts
            grep -q 'completePolicyInitialEnvironment' ${sc.opencodePlugin}/index.ts
            grep -q 'completePolicyInitialEnvironment' ${sc.opencodeV2Plugin}/index.ts
            mkdir -p config/safety-core
            printf '%s\n' '${
              builtins.toJSON {
                version = 1;
                policies = productionDslPolicies;
                projectPolicies = {
                  mode = "all";
                };
                bashAnalysis = {
                  maxFunctionDepth = 8;
                  maxNestedScriptDepth = 8;
                  maxSteps = 100;
                  maxWorkItems = 100;
                };
              }
            }' > config/safety-core/config.json
            test "$(SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core validate | grep -Ec '^[0-9a-f]{64}  /nix/store/')" -eq ${toString (builtins.length productionDslPolicies)}
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'git --version' > "$TMPDIR/explain-git.json"
            grep -q '"decision": "allow"' "$TMPDIR/explain-git.json"
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'cat credentials.json' > "$TMPDIR/explain-cat.json"
            grep -q '"decision": "deny"' "$TMPDIR/explain-cat.json"
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'echo uncovered' > "$TMPDIR/explain-echo.json"
            grep -q '"decision": "defer"' "$TMPDIR/explain-echo.json"
            mkdir -p project/.safety-core invalid/safety-core
            printf '%s\n' '{"version":1,"policies":["project.policy.json"]}' > project/.safety-core/config.json
            printf '%s\n' '{"language":"safety-core/bash-policy-v1","layer":"permission","select":[{"kind":"invocation"}],"registers":{},"folds":{},"options":{},"fragments":{},"start":"start","states":{"start":{"cases":[],"default":{"decision":"ignore"},"end":{"decision":"allow","reason":["project additive allow"]}}}}' > project/project.policy.json
            (cd project && SAFETY_CORE_CONFIG_HOME="$PWD/../config" ${sc.core}/bin/safety-core explain --json -- 'project-additive' > "$TMPDIR/explain-project.json")
            grep -q '"decision": "allow"' "$TMPDIR/explain-project.json"
            printf '%s\n' '{"version":1,"policies":["/missing.policy.json"],"projectPolicies":{"mode":"disabled"},"bashAnalysis":{"maxFunctionDepth":8,"maxNestedScriptDepth":8,"maxSteps":100,"maxWorkItems":100}}' > invalid/safety-core/config.json
            if SAFETY_CORE_CONFIG_HOME="$PWD/invalid" ${sc.core}/bin/safety-core validate; then
              echo "invalid policy source unexpectedly loaded" >&2
              exit 1
            fi
            mkdir -p state
            printf '%s' '{"hook_event_name":"SessionStart","session_id":"packaged-check","cwd":"'"$PWD"'"}' \
              | SAFETY_CORE_CONFIG_HOME="$PWD/config" SAFETY_CORE_STATE_HOME="$PWD/state" ${sc.claudeCodeHooks}/bash_policy.mjs
            printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git --version"},"session_id":"packaged-check","cwd":"'"$PWD"'"}' \
              | SAFETY_CORE_CONFIG_HOME="$PWD/config" SAFETY_CORE_STATE_HOME="$PWD/state" ${sc.claudeCodeHooks}/bash_policy.mjs \
              | grep -q '"permissionDecision":"allow"'
            printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat credentials.json"},"session_id":"packaged-check","cwd":"'"$PWD"'"}' \
              | SAFETY_CORE_CONFIG_HOME="$PWD/config" SAFETY_CORE_STATE_HOME="$PWD/state" ${sc.claudeCodeHooks}/bash_policy.mjs \
              | grep -q '"permissionDecision":"deny"'
            test -z "$(printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo uncovered"},"session_id":"packaged-check","cwd":"'"$PWD"'"}' \
              | SAFETY_CORE_CONFIG_HOME="$PWD/config" SAFETY_CORE_STATE_HOME="$PWD/state" ${sc.claudeCodeHooks}/bash_policy.mjs)"
            touch $out
          '';
          home-manager-config =
            let
              actualJson = pkgs.writeText "safety-core-home-manager-actual.json" (
                builtins.toJSON {
                  complete = completeEval.config;
                  pi = piEval.config;
                  disabledCli = disabledEval.cli;
                  disabledHookFile = disabledEval.claudeHookFile;
                  disabledHooks = disabledEval.hooks;
                  enabledCli = enabledEval.cli;
                  enabledHookFile = enabledEval.claudeHookFile;
                  enabledHooks = enabledEval.hooks;
                }
              );
              expectedJson = pkgs.writeText "safety-core-home-manager-expected.json" (
                builtins.toJSON {
                  completeSubset = {
                    version = 1;
                    projectPolicies = {
                      mode = "disabled";
                    };
                    bashAnalysis = {
                      maxFunctionDepth = 128;
                      maxNestedScriptDepth = 64;
                      maxSteps = 5;
                      maxWorkItems = 10000;
                    };
                    pi = {
                      autoApprove = false;
                      showFullCommand = true;
                    };
                  };
                  completePolicyCount = builtins.length completePolicySources;
                  pi = {
                    autoApprove = true;
                    judgeModel = "anthropic/claude-haiku";
                    showFullCommand = false;
                  };
                  disabledCli = [ ];
                  disabledHooks = { };
                  enabledHooks = expectedHooks;
                }
              );
            in
            pkgs.runCommand "safety-core-home-manager-config-check" { buildInputs = [ pkgs.nodejs_22 ]; } ''
              set -e
              ${pkgs.nodejs_22}/bin/node -e '
                const fs = require("node:fs");
                const assert = require("node:assert/strict");
                const actual = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
                const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
                for (const [key, value] of Object.entries(expected.completeSubset)) {
                  assert.deepStrictEqual(actual.complete[key], value, "complete " + key);
                }
                assert.strictEqual(actual.complete.policies.length, expected.completePolicyCount);
                assert.deepStrictEqual(actual.pi.pi, expected.pi);
                assert.deepStrictEqual(actual.disabledCli, expected.disabledCli);
                assert.strictEqual(actual.disabledHookFile, null);
                assert.deepStrictEqual(actual.disabledHooks, expected.disabledHooks);
                const enabledCli = actual.enabledCli;
                assert.strictEqual(enabledCli.length, 1);
                assert.ok(enabledCli[0].includes("safety-core"), enabledCli[0]);
                assert.ok(actual.enabledHookFile.includes("claude-code-safety-hooks"));
                assert.deepStrictEqual(actual.enabledHooks, expected.enabledHooks);
              ' ${actualJson} ${expectedJson}
              touch $out
            '';
        }
      );

      # Build against this flake's locked Nixpkgs rather than the consuming
      # configuration's package set, which pins the tree-sitter CLI used to
      # generate the bundled grammar while preserving the package-set API.
      overlays.default = final: _prev: {
        safety-core = scFor final.stdenv.hostPlatform.system;
      };
      homeManagerModules.default = import ./nix/permissions.nix;
      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          sc = scFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.bun
              pkgs.nodejs_22
              pkgs.typescript
              pkgs.python3
              pkgs.pre-commit
              pkgs.biome
              pkgs.nixfmt
              pkgs.markdownlint-cli
              pkgs.ruff
              sc.core
            ];
            shellHook = ''
              if [ -d .git ] && command -v pre-commit >/dev/null 2>&1; then
                pre-commit install >/dev/null
              fi
            '';
          };
        }
      );
    };
}
