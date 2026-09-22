# Task 6 Report: Global Config, Adapters, Validate/Explain

## Implementation

- Replaced the profile configuration export with the authoritative global `config.json` schema and removed all adapter reads of `profiles.json`.
- Added immutable `LoadedPolicyRuntime` loading: config resolution, source canonicalization, digesting, and code-policy imports occur once before adapter operation.
- Reduced authorization to the generic policy evaluator. Adapters now map only `allow`, `deny`, and `defer`; no policy-name presentation branches remain.
- Made adapter load/evaluation failures rejecting: Claude exits with a fatal hook status, OpenCode rejects execution, and Pi blocks the tool call.
- Added `safety-core validate` and `safety-core explain --json -- <source>`. Explain intentionally includes the complete unredacted model trace, including argv, environment, sources, digests, events, and every policy decision.
- Added a packaged Node 22 CLI and a Nix module that renders `safety-core/config.json`, supports explicit `policySources`, complete built-in sources, project-policy settings, analysis limits, and a generated transitional PR policy source.
- Retired profile-era Nix and package checks in favor of authoritative-config and packaged-CLI checks.

## RED

- Initial focused run exposed the expected profile-era integration gap and then two cutover defects:
  - Nix test evaluation did not provide `pkgs` to the module.
  - The complete-source helper appended a nested list, rendering one invalid policy path.
- Packaged CLI verification then exposed a duplicate shebang and unstaged source omission from the Nix flake source.

## GREEN

Commands and outcomes:

```text
bun test tests/policy-cli.test.ts tests/bash-config.test.ts tests/claude-code-bash-policy.test.ts tests/opencode-bash-guards.test.ts tests/opencode-read-only-cli.test.ts tests/pi-adapter.test.ts
13 pass, 0 fail, 1054 expect() calls

nix flake check
all checks passed
```

The adapter mapping test includes 1,024 generic allow/deny/defer permutations. CLI tests cover missing config fatality, source digests, ignored malformed `profiles.json`, and exact canary argv/environment trace content.

## Commit

Task 6 code and this report are committed together in the following commit.

## Concerns

- The CLI explain path deliberately emits unredacted modeled environment data. It is intended for explicit local diagnostics only and must not be routed into audit logs or harness-visible messages.
- No adversarial-model review was run because the operator explicitly directed that no reviewers be dispatched.
