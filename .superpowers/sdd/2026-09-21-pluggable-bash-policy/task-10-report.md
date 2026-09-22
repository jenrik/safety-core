# Task 10 Report: Enable Globally Gated Project DSL Policies

## Scope

Enabled project-local declarative Bash policies under the existing global
`projectPolicies` trust gate. The implementation keeps global source order for
trace presentation, permits project sources only when they are `.policy.json`,
and keeps denial dominance unchanged.

## Red

Added `tests/policy-project-config.test.ts` before changing the loader.

Command:

```text
bun test tests/policy-project-config.test.ts
```

Output before the loader change:

```text
3 pass
1 fail
PolicyStartupError: .../project-allow.policy.json: trusted code policy sources are permitted only in global configuration
```

The failure demonstrated that discovery already resolved an allowed project
file but the common loader rejected every project source, including DSL.

## Implementation

- Canonicalized selected global and applicable project configuration paths and
  retained a frozen SHA-256 identity for the exact bytes of each.
- Preserved nearest-ancestor-only discovery, exact canonical allowlist matching,
  disabled-mode non-discovery, strict project `version`/`policies` parsing, and
  relative-to-root project reference resolution.
- Allowed project `.policy.json` sources through the DSL loader while rejecting
  code policy sources before they can be imported.
- Preserved first-occurrence global-before-project source presentation while
  collapsing global/project aliases by canonical source path in the immutable
  loaded set.
- Extended runtime and Claude session manifests to version 2 with selected
  project root, configuration identities, scoped canonical policy sources, and
  every source digest. Isolated Claude hooks verify configuration bytes before
  reloading sources.
- Added strict manifest snapshot validation before policy loading.

## Tests

Focused Task 10 command:

```text
bun test tests/policy-project-config.test.ts tests/policy-config.test.ts tests/policy-loader.test.ts tests/policy-cli.test.ts tests/claude-code-bash-policy.test.ts tests/opencode-bash-guards.test.ts tests/pi-adapter.test.ts
```

Output:

```text
52 pass
0 fail
20598 expect() calls
```

Coverage includes disabled, allowlisted, and all modes; exact canonical
allowlist matching through symlinked roots; nearest-only discovery; strict
project schema and DSL-only enforcement; relative and absolute paths;
global/project canonical duplicate collapse; project permission expansion with
global guard denial dominance; CLI startup; and Claude, OpenCode, and Pi
startup behavior. The root-trust property runs 1,024 deterministic aliases.

Package check:

```text
nix flake check
```

Output:

```text
all checks passed!
```

Full suite check:

```text
bun test
```

Output:

```text
464 pass
13 fail
10 errors
44818 expect() calls
```

The 13 failures and 10 module errors are pre-existing outside Task 10: ten
modules import missing legacy public exports from `src/index.ts`; the dependent
`gh-pr-create-parser-failure` test fails for the same export boundary; and two
`policy-evaluate` expectations receive `defer` for invocations with unknown
missing environment bindings. The focused suite above is green.

## Self Review

- Confirmed project policy files cannot reach code import paths, including a
  `.policy.json` alias that canonicalizes to a code-source filename.
- Confirmed duplicate collapse uses canonical identity and retains the first
  global source scope when a project reference aliases it.
- Confirmed persisted manifests validate the exact canonical configuration
  paths and SHA-256 bytes before policy code or DSL loads.
- Confirmed project permission allows remain additive because the existing
  order-independent evaluator still evaluates all guard and permission policies
  and treats any denial as dominant.
- `git diff --check` passed.

## Commit

Commit created immediately after this report:

```text
feat(policy): load trusted project DSL policies
```

## Concerns

- No adversarial reviewer was dispatched, per the operator's explicit
  instruction to do all work without dispatching reviewers. Therefore no
  reviewer-driven corrections are pending for operator discussion.
- The full repository Bun suite remains blocked by the pre-existing failures
  listed above; Task 10's requested focused and package checks pass.
