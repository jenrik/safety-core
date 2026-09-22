# Task 11 report

## Changes

- Added DSL guard sources for secret reads, direct GitHub HTTP, kubectl, and unsupported fish command source.
- Added a code-vs-DSL differential corpus covering guard inputs, wrappers, ordering, redirects, safe paths, and 192 generated cases.
- Preserved immutable invocation/gap audit payloads in DSL deny/defer outcomes through the `event` audit reference.
- Switched Nix complete-policy sources and the CLI package check to the four DSL guard sources. Code sources remain packaged for differential tests.

## Parity evidence

The differential gate executes all walker-generated events against each paired code and DSL source and compares full decision values, including reason and audit.

It currently fails on the first generated walker event:

```
cat credentials.json: secret-read
code: { kind: "ignore" }
dsl:  { kind: "deny", reason: "bash reader on a protected secret file", audit: { invocation: event } }
```

The existing direct code-policy unit fixture for the equivalent invocation passes and returns deny. The failure is therefore a code-policy baseline/walker event incompatibility, not a tolerated stronger DSL result. The 192-case property gate fails for the same reason.

## Verification

- `bun test tests/policy-code-guards.test.ts`: PASS, 4 tests.
- `bun test tests/policy-parity.test.ts`: FAIL, two differential failures described above; seven tests pass.
- Required adapter command: FAILS before test execution because `tests/bash-guards.test.ts` imports missing `STRICT_BASH_PROFILE_EXECUTABLES` and `tests/bash-hard-block-policies.test.ts` imports missing `analyzeBashAuthorization` from `src/index.ts`.
- `nix flake check`: PASS after staging the DSL JSON inputs; all six x86_64-linux checks pass.
- `bun test tests/policy-dsl-evaluate.test.ts tests/policy-dsl-validate.test.ts tests/policy-code-guards.test.ts`: PASS, 29 tests and 725 assertions.
- `git diff --check`: PASS.

## Concerns

- The DSL selector model only supports one exact executable identity per source. The HTTP policy retains all-invocation selection and checks the reviewed finite HTTP-client table inside the machine so all six supported clients remain protected. Extending selector disjunction would be a separate language change.
- The code-vs-DSL gate must not be weakened until the walker/code guard mismatch is resolved. No parity claim should be made while it fails.
- The report intentionally records the failed required checks; no adversarial review was run because the operator explicitly prohibited dispatching reviewers.

## Fix Round 1

- Restored the compatibility `analyzeBashAuthorization`, `evaluateBashGuards`, `evaluateConfiguredBash`, `BashProfileSnapshot`, and `STRICT_BASH_PROFILE_EXECUTABLES` exports on top of the current walker. The guard facade includes the optional `gh pr create` overlay.
- Restored analyzer-derived diagnostics in the code parity sources; no static replacement diagnostics remain there.
- Changed DSL source selection to finite OR semantics and made the HTTP policy select each supported HTTP client by exact basename. Nonmatching invocations no longer select the HTTP source.
- Made reader-plus-protected-redirect evaluation choose the redirect denial before reader operands.
- Changed the package CLI smoke check to load and validate all four shipped DSL guard sources.
- `bun test tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts tests/opencode-bash-guards.test.ts tests/claude-code-bash-policy.test.ts tests/pi-adapter.test.ts tests/policy-code-guards.test.ts`: PASS, 94 tests and 1,514 assertions.
- `bun test tests/policy-parity.test.ts`: still FAILS. The strict differential assertion remains: a walker-projected `cat credentials.json` invocation evaluates as `ignore` in the imported code source but as DSL `deny`. This is not suppressed or classified as intentional.

## Completion

- The code wrapper was correct; the mismatch was an evaluator bug. Generic known-operand validation converted the literal string-set argument of `inStringSet` and `wordInAsciiCaseInsensitiveSet` into `UNKNOWN`, making composed reader/resource conditions fall through. Parsed URL operands had the same issue in `urlHostEquals`.
- The evaluator now preserves typed string-set, URL, and repository operands while retaining unknown propagation for genuine unknown inputs. `tests/policy-dsl-evaluate.test.ts` reproduces the nested `all`/`any`/`not` reader expression.
- EOF now evaluates terminal event predicates before an end terminal, so redirect-only commands are guarded. The secret policy emits the code analyzer's redirect diagnostic through a bounded modeled-redirect builtin; reader diagnostics are assembled with template expressions; GitHub diagnostics use the analyzer's sanitized steering formatter.
- HTTP sources use an OR-family of exact basename selectors. The full evaluator applies executable selectors as a finite disjunction, so non-HTTP invocations do not select the source.
- `kubectl get` now transitions from an unprotected first resource to the tail state, which retains audited defer decisions for protected later resources. The parity regression covers `kubectl get pod secrets/application`.
- `bun test tests/policy-parity.test.ts tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts tests/opencode-bash-guards.test.ts tests/claude-code-bash-policy.test.ts tests/pi-adapter.test.ts`: PASS, 101 tests and 4,872 assertions.
- `nix flake check`: PASS. The CLI smoke check loads all four DSL sources and verifies four validated source digests.

## Final Completion

### Changes

- Replaced the generic direct-GitHub-HTTP DSL diagnostic with the legacy
  analyzer's ordered finite endpoint table. It preserves all 16 API mappings:
  issue, pull request, release, workflow run, workflow, label, repository,
  search, and gist steering variants.
- Preserved raw-content detailed and fallback steering, including nested raw
  paths, sanitized host/path output, case-insensitive blocked hosts, trailing
  host dots, binding-derived generic steering, and unresolved-input
  blocked-domain diagnostics.
- Kept unknown API routes on the legacy generic `gh api '<path>'` fallback;
  route matching is finite policy state/case logic, not a formatter builtin.
- Added general lexical `pathAfterComponents`, `leadingAsciiDigits`, and
  immutable-input `inputBlockedDomain` primitives. They only project supplied
  values needed by finite template cases; they perform no formatting, lookup,
  callback, or policy-specific classification.
- Kept the constrained terminal-capture design. The HTTP source stores only an
  immutable URL input reference before terminal cases and derives host/path
  template values at the terminal boundary.
- Retained the four completed kubectl parity paths: protected first resources,
  protected later resources, positional-resource-only classification, and safe
  non-secret resources.

### Files

- `policies/dsl/github-http.policy.json`: finite ordered endpoint states,
  terminal captures, legacy fallback cases, and unresolved-domain parity.
- `policies/dsl/kubectl.policy.json`: accumulated positional-resource parity
  fixes retained.
- `policies/dsl/secret-read.policy.json`: accumulated redirect diagnostic
  parity fix retained.
- `src/policy/dsl/{ast,builtins,evaluate,validate}.ts`: constrained terminal
  capture support and typed lexical/input metadata projectors.
- `tests/policy-parity.test.ts`: explicit endpoint-category regressions plus
  96 generated numeric-route and nested-raw-path differential cases.
- `docs/policy-dsl.md`: capture debt boundary and complete closed builtin table.

### Verification

- `bun test tests/policy-parity.test.ts tests/policy-dsl-evaluate.test.ts tests/policy-dsl-validate.test.ts`
  - PASS: 40 tests, 5,330 assertions.
- `bun test tests/policy-parity.test.ts tests/bash-hard-block-policies.test.ts tests/bash-guards.test.ts tests/opencode-bash-guards.test.ts tests/claude-code-bash-policy.test.ts tests/pi-adapter.test.ts`
  - PASS: 104 tests, 6,112 assertions.
- `nix flake check`
  - PASS: all six x86_64-linux checks, including `cli-loads`.
- `git diff --check`
  - PASS.

### Commit

- This completion is committed as `fix(policy): complete GitHub HTTP DSL parity`.

### Concerns

- The terminal-template mechanism remains intentionally constrained design debt;
  no loops, recursion, macros, includes, dynamic lookup, callbacks, or
  policy-specific diagnostic formatter builtins were added.
- No adversarial review was run because the operator explicitly prohibited
  dispatching subagents/reviewers. The differential, mapping-category, and
  generated parity gates remain the available verification evidence.
