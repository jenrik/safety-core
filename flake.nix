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
          inherit (sc) piExtensionDir claudeCodeHooks codePolicies;
        });

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          lib = pkgs.lib;
          sc = pkgs.callPackage ./package.nix { };
        in {
          code-policies-runtime = pkgs.runCommand "safety-core-code-policies-runtime-check" { } ''
            set -e
            ${pkgs.nodejs_22}/bin/node --input-type=module -e '
              const [secretRead, githubHttp, kubectl, unsupportedShellSource, genericReadOnly, ghReadOnly, helmReadOnly, strictReadOnly, ghApi, ghPrCreate] = await Promise.all(
                process.argv.slice(1).map(async (path) => (await import(path)).default),
              );
               for (const policy of [secretRead, githubHttp, kubectl, unsupportedShellSource]) {
                 if (!Object.isFrozen(policy) || policy.apiVersion !== 1 || policy.layer !== "guard"
                   || typeof policy.evaluate !== "function") process.exit(1);
               }
               for (const policy of [genericReadOnly, ghReadOnly, helmReadOnly, strictReadOnly, ghApi, ghPrCreate]) {
                 if (!Object.isFrozen(policy) || policy.apiVersion !== 1 || policy.layer !== "permission"
                   || typeof policy.evaluate !== "function") process.exit(1);
               }
              const invocation = (executable, argv) => Object.freeze({
                kind: "invocation",
                executable: Object.freeze({ kind: "known", value: executable }),
                argv: Object.freeze(argv.map((value) => Object.freeze({ kind: "known", value }))),
                redirects: Object.freeze([]), environment: Object.freeze({}), missingBindings: "unset",
                assignments: Object.freeze({}), span: Object.freeze({ start: 0, end: 1 }),
                provenance: Object.freeze({ route: Object.freeze(["direct"]) }), inPipeline: false, processEffect: "none",
              });
              const gap = Object.freeze({
                kind: "execution-gap", reason: "unsupported-shell-source", environment: Object.freeze({}),
                missingBindings: "unset", span: Object.freeze({ start: 0, end: 1 }),
                provenance: Object.freeze({ route: Object.freeze(["direct"]) }), inPipeline: false, processEffect: "spawn-and-wait",
              });
              if (secretRead.evaluate(invocation("cat", ["credentials.json"])).kind !== "deny"
                 || githubHttp.evaluate(invocation("curl", ["https://api.github.com/user"])).kind !== "deny"
                 || kubectl.evaluate(invocation("kubectl", ["view-secret", "app"])).kind !== "deny"
                 || unsupportedShellSource.evaluate(gap).kind !== "deny"
                 || genericReadOnly.evaluate(invocation("git", ["diff", "HEAD"])).kind !== "allow"
                 || helmReadOnly.evaluate(invocation("helm", ["version"])).kind !== "allow"
                 || strictReadOnly.evaluate(invocation("docker", ["image", "ls"])).kind !== "allow"
                 || ghReadOnly.evaluate(invocation("gh", ["api", "user"])).kind !== "ignore"
                 || ghApi.evaluate(Object.freeze({ ...invocation("gh", ["api", "user"]), environment: Object.freeze({ GH_PAGER: Object.freeze({ kind: "known", value: "" }) }) })).kind !== "allow"
                 || ghPrCreate.evaluate(invocation("gh", ["pr", "create", "--repo", "github.com/acme/widgets", "--fill"])).kind !== "deny") process.exit(1);
            ' \
              ${sc.codePolicies.secretRead}/secret-read.policy.mjs \
              ${sc.codePolicies.githubHttp}/github-http.policy.mjs \
               ${sc.codePolicies.kubectl}/kubectl.policy.mjs \
               ${sc.codePolicies.unsupportedShellSource}/unsupported-shell-source.policy.mjs \
               ${sc.codePolicies.genericReadOnly}/generic-read-only.policy.mjs \
               ${sc.codePolicies.ghReadOnly}/gh-read-only.policy.mjs \
               ${sc.codePolicies.helmReadOnly}/helm-read-only.policy.mjs \
               ${sc.codePolicies.strictReadOnly}/strict-read-only.policy.mjs \
               ${sc.codePolicies.ghApi}/gh-api.policy.mjs \
               ${sc.codePolicies.ghPrCreate}/gh-pr-create.policy.mjs
            touch $out
          '';

          hooks-runtime = pkgs.runCommand "safety-core-hooks-runtime-check" { } ''
            set -e
            payload='{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"credentials.json"}}'

            set +e
            echo "$payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/secrets_policy.mjs > read.stdout 2> read.stderr
            code=$?
            set -e

            if [ "$code" -ne 2 ]; then
              echo "expected secrets_policy.mjs to exit 2 for a protected Read, got $code" >&2
              exit 1
            fi
            if [ -s read.stdout ] || ! grep -q "credentials.json" read.stderr; then
              echo "expected direct Read block reason only on stderr" >&2
              exit 1
            fi
            test -f ${sc.claudeCodeHooks}/bash_policy.mjs
            test ! -e ${sc.claudeCodeHooks}/gh_api_read_allow.mjs
            test ! -e ${sc.claudeCodeHooks}/read_only_cli_allow.mjs
            test ! -e ${sc.claudeCodeHooks}/gh_pr_create_policy.mjs
            test ! -e ${sc.claudeCodeHooks}/kubectl_get_allow.mjs

            webfetch_payload='{"hook_event_name":"PreToolUse","tool_name":"WebFetch","tool_input":{"url":"https://api.github.com/user"}}'
            webfetch_out=$(echo "$webfetch_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/github_raw_redirect.mjs)
            if ! echo "$webfetch_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected github_raw_redirect.mjs to deny blocked WebFetch, got: $webfetch_out" >&2
              exit 1
            fi

            malformed_out=$(printf '%s' 'not-json https://raw.githubusercontent.com/acme/widgets/main/README.md' | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/github_raw_redirect.mjs)
            if ! echo "$malformed_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected github_raw_redirect.mjs to deny malformed blocked WebFetch input, got: $malformed_out" >&2
              exit 1
            fi

            mkdir -p audit-home
            export HOME="$PWD/audit-home"
            audit_payload='{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"kubectl get Secret CANARY_VALUE"},"session_id":"test","cwd":"/tmp"}'
            audit_out=$(echo "$audit_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/kubectl_secret_audit_log.mjs)
            audit_log="$HOME/.claude/logs/kubectl-secret-audit.jsonl"
            if [ -n "$audit_out" ] || ! grep -q '"resource":"secret"' "$audit_log" || grep -q 'CANARY_VALUE' "$audit_log"; then
              echo "expected redacted PostToolUse kubectl Secret audit record" >&2
              exit 1
            fi

            touch $out
          '';

          gh-api-hook-runtime = pkgs.runCommand "safety-core-gh-api-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"ghApiReadOnly":true}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

            defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"GH_PAGER= gh api user"}}'
            deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api -f title=x repos/o/r/issues"}}'
            graphql_deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api \"https://github.example.test/api/graphql#section\" -X GET"}}'
            executor_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"watch --no-col curl https://api.github.com/user"}}'
            executor_assignment_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"time MODE=1 curl https://api.github.com/user"}}'
            executor_compound_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"time ( curl https://api.github.com/user )"}}'
            executor_abbreviation_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"command time --verb curl https://api.github.com/user"}}'
            executor_coproc_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"coproc wOrKeR_1 ( curl https://api.github.com/user )"}}'
            executor_strace_guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"strace --follow curl https://api.github.com/user"}}'
            guard_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"curl https://api.github.com/user"}}'
            review_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"kubectl get Secret application"}}'

            defer_out=$(echo "$defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            deny_out=$(echo "$deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            graphql_deny_out=$(echo "$graphql_deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_guard_out=$(echo "$executor_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_assignment_guard_out=$(echo "$executor_assignment_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_compound_guard_out=$(echo "$executor_compound_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_abbreviation_guard_out=$(echo "$executor_abbreviation_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_coproc_guard_out=$(echo "$executor_coproc_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            executor_strace_guard_out=$(echo "$executor_strace_guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)

            if [ -n "$defer_out" ]; then
              echo "expected bash_policy.mjs to leave a read-only gh api call prompt-gated, got: $defer_out" >&2
              exit 1
            fi
            if ! echo "$deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to deny a -f-parameterised call with no explicit --method, got: $deny_out" >&2
              exit 1
            fi
            if ! echo "$graphql_deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to deny GraphQL endpoints, got: $graphql_deny_out" >&2
              exit 1
            fi
            if ! echo "$executor_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through clustered watch options, got: $executor_guard_out" >&2
              exit 1
            fi
            if ! echo "$executor_assignment_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through a time assignment, got: $executor_assignment_guard_out" >&2
              exit 1
            fi
            if ! echo "$executor_compound_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through a time compound, got: $executor_compound_guard_out" >&2
              exit 1
            fi
            if ! echo "$executor_abbreviation_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through an abbreviated GNU time option, got: $executor_abbreviation_guard_out" >&2
              exit 1
            fi
            if ! echo "$executor_coproc_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through a named compound coprocess, got: $executor_coproc_guard_out" >&2
              exit 1
            fi
            if ! echo "$executor_strace_guard_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to preserve a guard denial through an abbreviated strace option, got: $executor_strace_guard_out" >&2
              exit 1
            fi

            set +e
            echo "$guard_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs > guard.stdout 2> guard.stderr
            guard_code=$?
            set -e
            if [ "$guard_code" -ne 0 ] || ! grep -q '"permissionDecision":"deny"' guard.stdout || [ -s guard.stderr ]; then
              echo "expected Bash guard denial as an exit-0 native override" >&2
              exit 1
            fi
            review_out=$(echo "$review_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
            if [ -n "$review_out" ]; then
              echo "expected kubectl Secret review to defer, got: $review_out" >&2
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

            deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh api -f title=x repos/o/r/issues"}}'
            deny_out=$(echo "$deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)

            if ! echo "$deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected SAFETY_CORE_CONFIG_HOME to enable ghApiReadOnly ahead of XDG_CONFIG_HOME, got: $deny_out" >&2
              exit 1
            fi

            touch $out
          '';

          command-profile-tests = pkgs.runCommand "safety-core-command-profile-tests"
            {
              nativeBuildInputs = [ pkgs.bash pkgs.bun pkgs.python3 ];
            } ''
            set -e
            mkdir test-work
            cp -r ${builtins.dirOf sc.opencodePluginFile}/src test-work/src
             cp -r ${builtins.dirOf sc.opencodePluginFile}/data test-work/data
             cp -r ${./scripts} test-work/scripts
             cp -r ${./docs} test-work/docs
            cp -r ${builtins.dirOf sc.opencodePluginFile}/node_modules test-work/node_modules
            cp -r ${./adapters} test-work/adapters
             cp -r ${./analysis} test-work/analysis
             cp -r ${./tests} test-work/tests
             cd test-work
             cp ${builtins.dirOf sc.opencodePluginFile}/tree-sitter-bash.wasm ./
             bun test tests/claude-code-bash-policy.test.ts
             bun test tests/claude-code-event-handlers.test.ts
             bun test tests/gh-pr-create-parser-failure.test.ts
             bun test tests/gh-pr-create.test.ts
              bun test ./tests/bash-configured.test.ts
             bun test tests/read-only-cli.test.ts
             bun test tests/gh-cli-reference.test.ts tests/gh-read-only-policy.test.ts
            bun test tests/opencode-read-only-cli.test.ts
            bun test tests/pi-adapter.test.ts
            bun test ./tests/bash-cst.test.ts
            SAFETY_CORE_PACKAGED_TESTS=1 bun test ./tests/bash-config.test.ts
            bun test ./tests/bash-environment.test.ts
            bun test ./tests/bash-expand.test.ts
            bun test ./tests/bash-runner.test.ts
            bun test ./tests/bash-walker.test.ts
            bun test ./tests/bash-dispatch.test.ts
            bun test ./tests/bash-hard-block-policies.test.ts
            bun test ./tests/bash-guards.test.ts
            bun test ./tests/bash-gh-policies.test.ts
            bun test ./tests/opencode-bash-guards.test.ts
            bun test ./tests/bash-equivalence.test.ts
            bun test ./tests/bash-performance.test.ts
            bun test ./tests/opencode-history-adapter.test.ts
            python -m unittest tests/test_replay_batches.py
            touch $out
          '';

          gh-pr-create-hook-runtime = pkgs.runCommand "safety-core-gh-pr-create-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"ghApiReadOnly":true,"ghPrCreate":{"enabled":true,"allowedRepositories":["acme/widgets"],"allowedOrganizations":[]}}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

             defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"GH_PROMPT_DISABLED=1 gh pr create --repo github.com/acme/widgets --fill"}}'
             unrelated_safe_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat README.md"}}'
            deny_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh alias set create-pr \"pr create --repo github.com/attacker/widgets\""}}'
            compound_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh pr create --repo github.com/acme/widgets --fill; gh api user"}}'

              defer_out=$(echo "$defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              unrelated_safe_out=$(echo "$unrelated_safe_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             deny_out=$(echo "$deny_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             compound_out=$(echo "$compound_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)

            if [ -n "$defer_out" ]; then
              echo "expected bash_policy.mjs to leave an allowlisted PR prompt-gated, got: $defer_out" >&2
              exit 1
            fi
            if [ -n "$unrelated_safe_out" ]; then
              echo "expected bash_policy.mjs to leave unrelated base-handler reads untouched, got: $unrelated_safe_out" >&2
              exit 1
            fi
            if ! echo "$deny_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected bash_policy.mjs to deny a non-allowlisted PR, got: $deny_out" >&2
              exit 1
            fi
            if ! echo "$compound_out" | grep -q '"permissionDecision":"deny"'; then
              echo "expected compound Bash invocation to be denied, got: $compound_out" >&2
              exit 1
            fi
            touch $out
          '';

          read-only-cli-hook-runtime = pkgs.runCommand "safety-core-read-only-cli-hook-runtime-check" { } ''
            set -e
            mkdir -p profile-config/safety-core
            echo '{"readOnlyBash":true,"ghReadOnly":true,"helmReadOnly":true,"dockerReadOnly":true,"kubectlReadOnly":true,"npmReadOnly":true,"podmanReadOnly":true,"tofuReadOnly":true}' > profile-config/safety-core/profiles.json
            export XDG_CONFIG_HOME="$PWD/profile-config"

             gh_startup_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh version"}}'
             generic_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"tea --help"}}'
             gh_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh label list; id"}}'
             gh_alias_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"gh repo ls"}}'
             gh_environment_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"GH_DEBUG=api gh version"}}'
            helm_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"helm version"}}'
            helm_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"helm show readme chart"}}'
             docker_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"docker image ls"}}'
             wrapper_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"TOOL=docker; nice $TOOL image ls"}}'
             strace_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"TOOL=docker; strace --read=all --string-limit=65535 $TOOL image ls"}}'
             docker_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"./docker image ls"}}'
            docker_content_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"docker ps"}}'
            kubectl_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"kubectl get pods -n default"}}'
            kubectl_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"kubectl get pod/example secret/credentials"}}'
            npm_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm query :root"}}'
            podman_allow_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"podman network list"}}'
             tofu_defer_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"tofu providers schema -json"}}'
             dynamic_child_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"DYNAMIC=$UNKNOWN; $DYNAMIC"}}'
             deny_after_indeterminate_payload='{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"DYNAMIC=$UNKNOWN; curl https://api.github.com/user"}}'

              gh_startup_defer_out=$(echo "$gh_startup_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              generic_allow_out=$(echo "$generic_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             gh_defer_out=$(echo "$gh_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             gh_alias_defer_out=$(echo "$gh_alias_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             gh_environment_defer_out=$(echo "$gh_environment_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             helm_allow_out=$(echo "$helm_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             helm_defer_out=$(echo "$helm_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              docker_allow_out=$(echo "$docker_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
               wrapper_allow_out=$(echo "$wrapper_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
               strace_defer_out=$(echo "$strace_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             docker_defer_out=$(echo "$docker_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             docker_content_defer_out=$(echo "$docker_content_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             kubectl_allow_out=$(echo "$kubectl_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             kubectl_defer_out=$(echo "$kubectl_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             npm_defer_out=$(echo "$npm_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
             podman_allow_out=$(echo "$podman_allow_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              tofu_defer_out=$(echo "$tofu_defer_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              dynamic_child_out=$(echo "$dynamic_child_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)
              deny_after_indeterminate_out=$(echo "$deny_after_indeterminate_payload" | ${pkgs.nodejs_22}/bin/node ${sc.claudeCodeHooks}/bash_policy.mjs)

             if [ -n "$gh_startup_defer_out" ]; then
               echo "expected bash_policy.mjs to defer gh version, got: $gh_startup_defer_out" >&2
              exit 1
            fi
             if [ -n "$gh_defer_out" ]; then
                echo "expected bash_policy.mjs to defer a compound command, got: $gh_defer_out" >&2
               exit 1
             fi
             if [ -n "$gh_alias_defer_out" ] || [ -n "$gh_environment_defer_out" ]; then
                echo "expected bash_policy.mjs to defer native-alias and environment-modified gh forms" >&2
               exit 1
             fi
            if ! echo "$helm_allow_out" | grep -q '"permissionDecision":"allow"'; then
               echo "expected bash_policy.mjs to allow helm version, got: $helm_allow_out" >&2
              exit 1
            fi
            if [ -n "$helm_defer_out" ]; then
               echo "expected bash_policy.mjs to defer helm show readme, got: $helm_defer_out" >&2
              exit 1
            fi
             if ! echo "$docker_allow_out" | grep -q '"permissionDecision":"allow"'; then
               echo "expected bash_policy.mjs to allow docker image ls, got: $docker_allow_out" >&2
              exit 1
             fi
             if ! echo "$generic_allow_out" | grep -q '"permissionDecision":"allow"'; then
                echo "expected bash_policy.mjs to allow tea --help, got: $generic_allow_out" >&2
               exit 1
             fi
              if ! echo "$wrapper_allow_out" | grep -q '"permissionDecision":"allow"'; then
                 echo "expected bash_policy.mjs to allow a stateful assignment through a wrapper, got: $wrapper_allow_out" >&2
                exit 1
              fi
              if [ -n "$strace_defer_out" ]; then
                 echo "expected bash_policy.mjs to defer credential-capable strace output, got: $strace_defer_out" >&2
                exit 1
              fi
            if [ -n "$docker_defer_out" ]; then
               echo "expected bash_policy.mjs to defer an explicit Docker path, got: $docker_defer_out" >&2
              exit 1
            fi
            if [ -n "$docker_content_defer_out" ]; then
               echo "expected bash_policy.mjs to defer Docker command-column output, got: $docker_content_defer_out" >&2
              exit 1
            fi
            if ! echo "$kubectl_allow_out" | grep -q '"permissionDecision":"allow"'; then
               echo "expected bash_policy.mjs to allow namespaced kubectl get, got: $kubectl_allow_out" >&2
              exit 1
            fi
            if [ -n "$kubectl_defer_out" ]; then
               echo "expected bash_policy.mjs to defer a later protected kubectl resource, got: $kubectl_defer_out" >&2
              exit 1
            fi
            if [ -n "$npm_defer_out" ]; then
               echo "expected bash_policy.mjs to defer npm package-object output, got: $npm_defer_out" >&2
              exit 1
            fi
            if ! echo "$podman_allow_out" | grep -q '"permissionDecision":"allow"'; then
               echo "expected bash_policy.mjs to allow a Podman list alias, got: $podman_allow_out" >&2
              exit 1
            fi
             if [ -n "$tofu_defer_out" ]; then
                echo "expected bash_policy.mjs to defer configuration-aware OpenTofu reads, got: $tofu_defer_out" >&2
              exit 1
             fi
             if [ -n "$dynamic_child_out" ]; then
                echo "expected bash_policy.mjs to leave a dynamic child permission untouched, got: $dynamic_child_out" >&2
               exit 1
             fi
             if ! echo "$deny_after_indeterminate_out" | grep -q '"permissionDecision":"deny"'; then
                echo "expected bash_policy.mjs to deny after an indeterminate child, got: $deny_after_indeterminate_out" >&2
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
            const startup = { status: "ask" };
            await hooks["permission.ask"]({ type: "bash", pattern: "gh version" }, startup);
            if (startup.status !== "ask") {
              console.error(`expected packaged OpenCode plugin to defer gh version, got ''${startup.status}`);
              process.exit(1);
            }
            const defer = { status: "ask" };
            await hooks["permission.ask"]({ type: "bash", pattern: "gh label list" }, defer);
            if (defer.status !== "ask") {
              console.error(`expected packaged OpenCode plugin to defer gh label list, got ''${defer.status}`);
              process.exit(1);
            }
            EOF

            mkdir -p profile-config/safety-core
            echo '{"ghReadOnly":true}' > profile-config/safety-core/profiles.json
            export SAFETY_CORE_CONFIG_HOME="$PWD/profile-config"
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
              bashAllow = (evaled.config.programs.opencode.settings.permission or { }).bash or { };
              claudeBashHooks = builtins.concatLists (map (entry: if entry.matcher == "Bash" then entry.hooks else [ ]) evaled.config.programs.claude-code.settings.hooks.PreToolUse);
              claudeBashCommands = map (hook: hook.command) claudeBashHooks;
            in
             assert bashAllow == { };
            assert claudeBashCommands == [ "$HOME/.claude/hooks/bash_policy.mjs" ];
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
                     config.programs.safetyCorePermissions.bashAnalysis = {
                       maxFunctionDepth = 7;
                       maxNestedScriptDepth = 6;
                       maxSteps = 5;
                       maxWorkItems = 4;
                     };
                  }
                ];
              };
              profile = builtins.fromJSON evaled.config.xdg.configFile."safety-core/profiles.json".text;
            in
            assert profile.ghPrCreate.enabled;
             assert profile.ghPrCreate.allowedRepositories == [ "acme/widgets" ];
             assert profile.ghPrCreate.allowedOrganizations == [ "trusted-org" ];
             assert profile.bashAnalysis.maxFunctionDepth == 7;
             assert profile.bashAnalysis.maxNestedScriptDepth == 6;
             assert profile.bashAnalysis.maxSteps == 5;
             assert profile.bashAnalysis.maxWorkItems == 4;
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
                    config.programs.safetyCorePermissions.profiles.dockerReadOnly.enable = true;
                  }
                ];
              };
              profile = builtins.fromJSON evaled.config.xdg.configFile."safety-core/profiles.json".text;
            in
            assert profile.ghReadOnly;
            assert profile.helmReadOnly;
            assert profile.dockerReadOnly;
            pkgs.runCommand "safety-core-read-only-cli-profile-eval-check" { } "touch $out";
        });

      overlays.default = final: _prev: {
        safety-core = final.callPackage ./package.nix { };
      };

      homeManagerModules.default = import ./nix/permissions.nix;

      devShells = forAllSystems (system: {
        default = (pkgsFor system).mkShell {
          packages = [
            (pkgsFor system).bun
            (pkgsFor system).nodejs_22
            (pkgsFor system).typescript
            (pkgsFor system).python3
            (pkgsFor system).python3Packages.marimo
            (pkgsFor system).python3Packages.polars
          ];
        };
      });
    };
}
