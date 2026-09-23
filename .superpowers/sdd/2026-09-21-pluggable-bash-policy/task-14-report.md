# Task 14 Report: Final Verification and Operator-Gated Adversarial Review

## Status

Steps 1-3 passed at commit `48c5d2d3aade51a53b29e8c138af689a9a1cd721`.

No implementation files were modified, staged, committed, pushed, or otherwise
changed. All smoke configuration and policy sources were non-secret temporary
files under `/tmp/safety-core-task14.SJfNOq`. The packaged CLI used was:

```text
/nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core
```

The required adversarial review was not conducted. It remains controller-owned
and must be presented to the operator before any review-driven correction.

## Step 1: Focused Policy Platform Suite

Command (exit status `0`):

```bash
bun test tests/policy-evaluate.test.ts tests/policy-config.test.ts tests/policy-loader.test.ts tests/policy-events.test.ts tests/policy-executable.test.ts tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-project-config.test.ts tests/policy-cli.test.ts tests/policy-session.test.ts tests/policy-parity.test.ts
```

Verbatim result:

```text
bun test v1.3.13 (bf2e2cec)

 130 pass
 0 fail
 30208 expect() calls
Ran 130 tests across 12 files. [25.40s]
```

## Step 2: Complete Repository and Flake Checks

Command (exit status `0`):

```bash
bun test tests/*.test.ts
```

Verbatim result:

```text
bun test v1.3.13 (bf2e2cec)

tests/bash-performance.test.ts:
Task 10 cap-exhaustion function-depth: 13.8 ms
Task 10 cap-exhaustion nested-script-depth: 28.9 ms
Task 10 cap-exhaustion steps: 402.7 ms
Task 10 cap-exhaustion work-items: 10.9 ms
Task 10 assignment calibration 10000: 550.0 ms
Task 10 assignment calibration 15000: 758.7 ms
Task 10 assignment calibration 20000: 1068.9 ms
Task 10 assignment calibration 25000: 1326.0 ms
Branch-heavy sequential-conditionals: 20.3 ms
Branch-heavy conditional-loop: 13.1 ms
Branch-heavy short-circuit-chain: 8.4 ms
Branch-heavy mixed-short-circuit-projection: 153.4 ms

 708 pass
 0 fail
 57392 expect() calls
Ran 708 tests across 42 files. [46.73s]
```

Command (exit status `0`):

```bash
python -m unittest tests/test_replay_batches.py
```

Verbatim result:

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.020s

OK
```

Command (exit status `0`):

```bash
nix flake check
```

Verbatim result:

```text
evaluating flake...
checking flake output 'packages'...
checking derivation packages.x86_64-linux.piExtensionDir...
derivation evaluated to /nix/store/9m9cswwb3rqncshza63m5l7zwq6g7px8-safety-core-pi.drv
checking derivation packages.x86_64-linux.opencodePlugin...
derivation evaluated to /nix/store/njh1hwzzj7mbm4dflqc9g5axrqcjmxsy-safety-core-opencode.drv
checking derivation packages.x86_64-linux.claudeCodeHooks...
derivation evaluated to /nix/store/lq4mrgnkyx4qs2w0afmjvw54mgkvr6az-claude-code-safety-hooks-0.drv
checking derivation packages.x86_64-linux.safetyCoreCli...
derivation evaluated to /nix/store/dgvin53vw6pm6q8qyjjy6yg6k7fg3ycm-safety-core-0.drv
checking derivation packages.x86_64-linux.core...
derivation evaluated to /nix/store/jz927qj3ii0zyffgn02r0lzl4ylswnx7-safety-core-core-0.drv
checking derivation packages.x86_64-linux.policySources...
derivation evaluated to /nix/store/zcb1wbsphdvn83lgwc8c2ifsk9pfg9ba-safety-core-policy-sources-0.drv
checking derivation packages.x86_64-linux.default...
derivation evaluated to /nix/store/dgvin53vw6pm6q8qyjjy6yg6k7fg3ycm-safety-core-0.drv
checking flake output 'checks'...
checking derivation checks.x86_64-linux.code-policies-runtime...
derivation evaluated to /nix/store/q8ww9m59mc8qj7x69d9jcqq7vxzbgm9i-safety-core-code-policies-runtime-check.drv
checking derivation checks.x86_64-linux.cli-loads...
derivation evaluated to /nix/store/aqw57zkjgnpvaffk0pfli5rnpbq9yc8k-safety-core-cli-loads-check.drv
checking flake output 'overlays'...
checking overlay 'overlays.default'...
checking flake output 'homeManagerModules'...
warning: unknown flake output 'homeManagerModules'
checking flake output 'devShells'...
checking derivation devShells.x86_64-linux.default...
derivation evaluated to /nix/store/8x7cn1cg6kh0b8czk30hqx109rczwgsk-nix-shell.drv
running 0 flake checks...
all checks passed!
warning: The check omitted these incompatible systems: aarch64-linux
Use '--all-systems' to check all.
```

## Step 3: Packaged CLI Smoke Matrix

Package-resolution commands (each exit status `0`):

```bash
nix build --no-link --print-out-paths .#safetyCoreCli
nix build --no-link --print-out-paths .#policySources
```

Verbatim output:

```text
/nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0
/nix/store/xfjk6bak2ms479xj0x86iih4hf0nmgj8-safety-core-policy-sources-0
```

All explain invocations used `env -i` with only non-secret `PATH`,
`SAFETY_CORE_CONFIG_HOME`, and, for the canary case, `CANARY_INHERITED`.

### Validate

Command (exit status `0`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/home /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core validate
```

Verbatim output (two canonical sources):

```text
d4114f3394b280d1794f532ae6235bc8651965e96ff095ab2454a7ae922d36e8  /tmp/safety-core-task14.SJfNOq/allow.policy.mjs
4bf7b5e4c385989d0dc970abc576eea272164ae9259ec2356ed4484fac6c3895  /nix/store/xfjk6bak2ms479xj0x86iih4hf0nmgj8-safety-core-policy-sources-0/secret-read.policy.json
```

### Allowed Explain and Exact Canaries

Command (exit status `0`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/home CANARY_INHERITED=inherited-value /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core explain --json -- "CANARY_ASSIGN=exact-value printf '%s' CANARY_ARG"
```

Verbatim relevant JSON values:

```json
{
  "decision": "allow",
  "analysis": { "complete": true },
  "argv": [
    { "kind": "known", "value": "%s" },
    { "kind": "known", "value": "CANARY_ARG" }
  ],
  "environment": {
    "CANARY_INHERITED": { "kind": "known", "value": "inherited-value" },
    "CANARY_ASSIGN": { "kind": "known", "value": "exact-value" }
  },
  "assignments": {
    "CANARY_ASSIGN": { "kind": "known", "value": "exact-value" }
  }
}
```

The full explain trace contained one modeled event and two source decisions:
the temporary permission source allowed and the packaged secret-read guard
ignored.

### Denied Explain

Command (exit status `0`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/home /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core explain --json -- "cat credentials.json"
```

Verbatim decision and reason:

```json
{
  "decision": "deny",
  "analysis": { "complete": true },
  "reason": [
    { "kind": "literal", "value": "bash `cat` on 'credentials.json'" }
  ]
}
```

The trace contained one modeled event and two source decisions: temporary
permission source `ignore`, packaged secret-read guard `deny`.

### Uncovered Explain

Command (exit status `0`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/home /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core explain --json -- "echo uncovered"
```

Verbatim decision:

```json
{
  "decision": "defer",
  "analysis": { "complete": true }
}
```

The trace contained one modeled event and two `ignore` source decisions.

### Project-Additive Explain

Command (exit status `0`, working directory
`/tmp/safety-core-task14.SJfNOq/project`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/home /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core explain --json -- "project-cmd"
```

Verbatim decision and project source identity:

```json
{
  "decision": "allow",
  "analysis": { "complete": true },
  "canonicalPath": "/tmp/safety-core-task14.SJfNOq/project/project.policy.json",
  "sha256": "2fcf6c0c97890b918ada61e3e886fdae14b02ba633311677341a1a22aa944aa2",
  "reason": [
    { "kind": "literal", "value": "project additive allow" }
  ]
}
```

The trace contained one modeled event and three source decisions: global
permission `ignore`, packaged guard `ignore`, project permission `allow`.

### Fatal Invalid Source

Command (exit status `1`):

```bash
env -i PATH=/usr/bin:/bin SAFETY_CORE_CONFIG_HOME=/tmp/safety-core-task14.SJfNOq/invalid-home /nix/store/1vca3871srfihdwn6dy9h49xxlhiqd8s-safety-core-0/bin/safety-core validate
```

Verbatim stderr:

```text
safety-core: /tmp/safety-core-task14.SJfNOq/missing.policy.mjs: cannot canonicalize policy source
```

## Blockers and Execution Notes

- No blocker prevented Steps 1-3 from passing.
- `nix flake check` emitted the two warnings reproduced verbatim above. It still
  exited `0` with `all checks passed!`.
- The first temporary smoke configuration incorrectly referenced the packaged
  source at `/nix/store/xfjk6bak2ms479xj0x86iih4hf0nmgj8-safety-core-policy-sources-0/dsl/secret-read.policy.json` rather than its package-root location. Each of
  the five initial smoke invocations exited `1` with this verbatim error:

  ```text
  safety-core: /nix/store/xfjk6bak2ms479xj0x86iih4hf0nmgj8-safety-core-policy-sources-0/dsl/secret-read.policy.json: cannot canonicalize policy source
  ```

  Listing the package showed `secret-read.policy.json` at the package root. The
  temporary config was corrected to that path; every final smoke case above
  then had the expected result. This was a test-fixture path correction, not a
  product failure.
- The adversarial-review and operator-discussion steps are intentionally not
  performed by this verification implementer. The controller must dispatch the
  review and present every Critical and Important finding to the operator before
  any correction is made.

## Operator-Approved Corrections

The operator reviewed the adversarial findings and approved only the following
corrections. This report records their final implementation.

### Complete inherited environment for adapter policy evaluation

- Added `completePolicyInitialEnvironment`, a verified snapshot that retains
  every inherited environment value, including empty strings, and proves omitted
  names unset. This preserves the model's known/unknown/unset behavior without
  filtering or redacting policy inputs.
- OpenCode, Pi, and Claude now use that complete snapshot for configuration
  loaded policy evaluation. The legacy filtered `policyInitialEnvironment`
  remains only for the compatibility profile facades that explicitly require its
  reviewed reduced snapshot.
- Added adapter regressions using a real DSL permission policy. OpenCode covers
  64 distinct inherited canaries and confirms absence remains unapproved; Pi and
  Claude cover exact inherited canaries. The CLI regression verifies a real DSL
  `environmentValueEquals(environmentLookup(...))` allow and the unchanged
  explain event/decision trace with the exact inherited value.
- The trace regression exposed that `environmentValueEquals` was incorrectly
  treated as a string-only builtin before dispatch. Its binding-value input is
  now handled by the typed environment builtin path, allowing exact known values
  while retaining unknown and unset behavior.

### Pi startup failure

- Pi now awaits parser and runtime initialization during `session_start`.
  Initialization failures poison the extension and reject the session-start
  callback, so the host cannot proceed with an active policy session. Later Bash
  calls remain blocked without invoking policy evaluation.

### Packaged production inventory gate

- Expanded `checks.x86_64-linux.cli-loads` to load all 27 packaged DSL sources:
  secret, GitHub HTTP, kubectl, unsupported-shell-source, generic/gh/helm
  read-only families, all strict profiles, and the generated `gh pr create`
  source.
- The package gate verifies OpenCode/Pi packaged adapter artifacts contain the
  complete-environment runtime path, and executes packaged CLI/Claude artifacts
  for allow, deny, defer, project-additive, and fatal-source cases.

### Accepted Claude dependency risk

The operator accepted the known risk that a Claude isolated-hook manifest fixes
configured code-policy entry files but cannot completely freeze bytes of allowed
imported dependencies. A dependency changed between hooks can affect later
evaluation. `docs/policy-authoring.md` now directs operators to use
self-contained bundled policy sources and cross-references the existing Claude
session-identity and filesystem TOCTOU documentation. No dependency snapshot
work was added.

## Correction Verification

All commands exited `0` unless noted.

```bash
bun test tests/policy-evaluate.test.ts tests/policy-config.test.ts tests/policy-loader.test.ts tests/policy-events.test.ts tests/policy-executable.test.ts tests/policy-dsl-validate.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-performance.test.ts tests/policy-project-config.test.ts tests/policy-cli.test.ts tests/policy-session.test.ts tests/policy-parity.test.ts tests/gh-read-only-policy.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts tests/claude-code-bash-policy.test.ts
```

```text
171 pass
0 fail
33838 expect() calls
Ran 171 tests across 16 files. [32.81s]
```

```bash
bun test tests/*.test.ts
```

```text
713 pass
0 fail
57723 expect() calls
Ran 713 tests across 42 files. [55.65s]
```

```bash
python -m unittest tests/test_replay_batches.py
```

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.020s

OK
```

```bash
git diff --check
nix build --no-link --option builders '' .#checks.x86_64-linux.cli-loads
nix flake check --option builders ''
```

The package gate built the complete production inventory and passed every
packaged CLI/Claude decision path. `nix flake check` evaluated all package
artifacts and ran both configured checks successfully. It emitted only the
existing `homeManagerModules` unknown-output warning and the expected
`aarch64-linux` omission warning.

## Commit

`be68c3f fix(policy): restore complete adapter environment`

## Operator-Authorized Final Fix: Three-Valued Environment Equality

The operator approved this focused post-final-wave correction. No additional
review was dispatched, per the operator's instruction.

`environmentValueEquals` now returns `UNKNOWN` for unknown environment
bindings and unknown comparison values. It returns boolean results only for
known bindings and keeps proven-unset bindings unequal. Therefore negation
cannot turn an unknown environment binding into an allow.

The production DSL corpus has one use of `environmentValueEquals`:
`policies/dsl/gh-api.policy.json` evaluates `GH_PAGER` through an `any` within
the terminal direct-execution proof. The unknown result now propagates through
that expression, preserving a conservative `defer`. Existing OpenCode, Pi,
and Claude adapter tests retain their real-DSL inherited-environment and
absent-binding coverage.

### Verification

All commands exited `0`.

```bash
bun test tests/policy-dsl-evaluate.test.ts tests/policy-dsl-validate.test.ts tests/policy-dsl-performance.test.ts tests/bash-environment.test.ts tests/policy-cli.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts tests/claude-code-bash-policy.test.ts tests/gh-read-only-policy.test.ts
```

```text
98 pass
0 fail
8153 expect() calls
Ran 98 tests across 9 files. [3.86s]
```

The evaluator suite adds a complete known-equal, known-unequal, unknown, and
proven-unset matrix under positive and negated conditions, plus 128 generated
known-binding equality cases.

```bash
bun test tests/*.test.ts
```

```text
715 pass
0 fail
58243 expect() calls
Ran 715 tests across 42 files. [55.51s]
```

```bash
python -m unittest tests/test_replay_batches.py
```

```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.020s

OK
```

```bash
nix build --no-link --option builders '' .#checks.x86_64-linux.cli-loads
nix flake check --option builders ''
```

The packaged CLI gate and both configured flake checks passed. `nix flake
check` emitted only the existing unknown `homeManagerModules` output warning
and the expected `aarch64-linux` omission warning.

### Commit

`fix(policy): preserve unknown environment equality` (this report's changeset)
