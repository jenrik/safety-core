{
  description = "Shared TS safety-policy core for pi/opencode/claude-code coding-agent hooks";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      scFor = system: (pkgsFor system).callPackage ./package.nix { };
    in {
      packages = forAllSystems (system:
        let sc = scFor system;
        in {
          inherit (sc) piExtensionDir opencodePlugin opencodeV2Plugin opencodeTuiPlugin claudeCodeHooks safetyCoreCli core policySources;
          default = sc.core;
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sc = scFor system;
          prPolicy = sc.mkGhPrCreateDslPolicy {
            allowedRepositories = [ "acme/widgets" ];
            allowedOrganizations = [ ];
          };
          productionDslPolicies = [
            sc.dslPolicies.secretRead
            sc.dslPolicies.githubHttp
            sc.dslPolicies.kubectl
            sc.dslPolicies.unsupportedShellSource
            sc.dslPolicies.genericReadOnly
            sc.dslPolicies.ghReadOnly
            sc.dslPolicies.helmReadOnly
            sc.dslPolicies.ghApi
          ] ++ sc.dslPolicies.strictReadOnly ++ [ "${prPolicy}/gh-pr-create.policy.json" ];
        in {
          code-policies-runtime = pkgs.runCommand "safety-core-code-policies-runtime-check" { } ''
            set -e
            ${pkgs.nodejs_22}/bin/node --input-type=module -e '
              const policy = (await import(process.argv[1])).default;
              if (!Object.isFrozen(policy) || policy.apiVersion !== 1 || typeof policy.evaluate !== "function") process.exit(1);
            ' ${sc.codePolicies.apiFixture}/api-fixture.policy.mjs
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
            printf '%s\n' '${builtins.toJSON {
              version = 1;
              policies = productionDslPolicies;
              projectPolicies = { mode = "all"; };
              bashAnalysis = { maxFunctionDepth = 8; maxNestedScriptDepth = 8; maxSteps = 100; maxWorkItems = 100; };
            }}' > config/safety-core/config.json
            test "$(SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core validate | grep -Ec '^[0-9a-f]{64}  /nix/store/')" -eq 28
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'git --version' | grep -q '"decision": "allow"'
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'cat credentials.json' | grep -q '"decision": "deny"'
            SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.core}/bin/safety-core explain --json -- 'echo uncovered' | grep -q '"decision": "defer"'
            mkdir -p project/.safety-core invalid/safety-core
            printf '%s\n' '{"version":1,"policies":["project.policy.json"]}' > project/.safety-core/config.json
            printf '%s\n' '{"language":"safety-core/bash-policy-v1","layer":"permission","select":[{"kind":"invocation"}],"registers":{},"folds":{},"options":{},"fragments":{},"start":"start","states":{"start":{"cases":[],"default":{"decision":"ignore"},"end":{"decision":"allow","reason":["project additive allow"]}}}}' > project/project.policy.json
            (cd project && SAFETY_CORE_CONFIG_HOME="$PWD/../config" ${sc.core}/bin/safety-core explain --json -- 'project-additive' | grep -q '"decision": "allow"')
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
        });

      # Build against this flake's locked Nixpkgs rather than the consuming
      # configuration's package set, which pins the tree-sitter CLI used to
      # generate the bundled grammar while preserving the package-set API.
      overlays.default = final: _prev: {
        safety-core = scFor final.stdenv.hostPlatform.system;
      };
      homeManagerModules.default = import ./nix/permissions.nix;
      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sc = scFor system;
        in {
          default = pkgs.mkShell { packages = [
            pkgs.bun pkgs.nodejs_22 pkgs.typescript pkgs.python3 sc.core
          ]; };
          redact = pkgs.mkShell {
            packages = [ pkgs.python312 pkgs.uv pkgs.protobuf pkgs.nodejs_22 pkgs.bun ];
            # uv-installed spaCy/NumPy wheels need these shared libraries on NixOS.
            shellHook = ''
              export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.stdenv.cc.cc.lib pkgs.zlib ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            '';
          };
        });
    };
}
