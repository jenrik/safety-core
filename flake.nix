{
  description = "Shared TS safety-policy core for pi/opencode/claude-code coding-agent hooks";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in {
      packages = forAllSystems (system:
        let sc = (pkgsFor system).callPackage ./package.nix { };
        in {
          inherit (sc) piExtensionDir claudeCodeHooks safetyCoreCli;
          default = sc.safetyCoreCli;
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          sc = pkgs.callPackage ./package.nix { };
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
            test -x ${sc.safetyCoreCli}/bin/safety-core
            mkdir -p config/safety-core
            printf '%s\n' '{"version":1,"policies":["${sc.dslPolicies.secretRead}","${sc.dslPolicies.githubHttp}","${sc.dslPolicies.kubectl}","${sc.dslPolicies.unsupportedShellSource}"],"projectPolicies":{"mode":"disabled"},"bashAnalysis":{"maxFunctionDepth":8,"maxNestedScriptDepth":8,"maxSteps":100,"maxWorkItems":100}}' > config/safety-core/config.json
            test "$(SAFETY_CORE_CONFIG_HOME="$PWD/config" ${sc.safetyCoreCli}/bin/safety-core validate | grep -Ec '^[0-9a-f]{64}  /nix/store/')" -eq 4
            touch $out
          '';
        });

      overlays.default = final: _prev: { safety-core = final.callPackage ./package.nix { }; };
      homeManagerModules.default = import ./nix/permissions.nix;
      devShells = forAllSystems (system: {
        default = (pkgsFor system).mkShell { packages = [
          (pkgsFor system).bun (pkgsFor system).nodejs_22 (pkgsFor system).typescript (pkgsFor system).python3
        ]; };
      });
    };
}
