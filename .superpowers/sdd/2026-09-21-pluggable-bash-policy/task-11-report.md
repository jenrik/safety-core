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
