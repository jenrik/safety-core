# `bash-test` policy scope

## Intent

Automatically authorize direct Bash `test` and `[` predicate evaluation. The
policy permits the complete operand grammar as Bash evaluates it, while proving
the direct builtin target and the structural closing bracket required by `[`.

## Protected action and asset

The protected boundary is automatic authorization of one modeled direct Bash
predicate builtin invocation. The policy does not authorize a nested command,
environment mutation, filesystem content access, or a later shell-tool call.
Redirect-owned file opens remain independently governed by harness file
permissions.

## In scope

The policy permits exactly these forms:

- The immediate, unqualified executable spelling is `test` or `[` and immediate
  lookup resolves it to a Bash builtin rather than a function or external
  executable.
- There are no command-prefix assignments and every operand is statically
  resolved.
- Every Bash predicate operand form is in scope for `test`, including string,
  integer, variable, descriptor, and filesystem-metadata predicates such as
  `-v`, `-e`, `-r`, and `-t`. The policy deliberately does not reproduce Bash's
  semantic predicate grammar; malformed expressions can still fail in Bash.
- For `[`, the last operand is exactly `]`; the preceding operands are otherwise
  handled with the same broad predicate scope as `test`.
- Supported redirections are in scope, but their file opens are separately
  checked by the harness.

Examples include `test -e ./file`, `test -v array[key]`, `[ "$name" = value ]`,
and `[ -r ./file ] > ./result.txt`.

## Out of scope and threat-model exclusions

The policy defers `[` without a final `]`, `[` with operands after its final
`]`, unresolved operands, prefix assignments, path-qualified spellings,
function shadowing, and any non-builtin resolution. Nested commands that
produce operands require independent authorization.

This policy excludes adversarial shell-language bypasses and assumes complete
facts from the Bash parser/walker. The unresolved question of how safety-core
models these predicate builtins and their metadata checks is tracked in
[`docs/future-work.md`](../../../docs/future-work.md); the policy does not turn
a metadata predicate into authorization to read file content.

## Assumptions and non-goals

The policy assumes the direct Bash predicate builtins themselves have no
command-specific host effect beyond status and metadata inspection. It does
not claim that a predicate's answer is stable, that a referenced filesystem
object exists, or that its metadata access is a content read. It also does not
authorize a redirected file path; harness file permission outcomes remain
dominant.

The independent-shell-per-tool-call model does not eliminate effects on later
commands in the same source. This policy covers only the predicate invocation;
every other reachable invocation must independently be covered.

## Expected outcomes

- **permit:** exact in-scope `test` or bracket-terminated `[` invocations return
  `allow` from this policy. Final automatic approval also requires all other
  modeled invocations and harness file checks to allow.
- **defer:** every form outside the stated grammar returns `defer`, including
  malformed bracket termination, unknown operands, assignments, and non-builtin
  resolution. A harness ask/unknown result for a redirected path also prevents
  final automatic approval.
- **deny:** this policy has no deny rule. Independent guards and harness file
  permission checks can still deny the request.

Because an `allow` requires a proven Bash builtin rather than an unresolved
external target, this policy deliberately leaves its executable selectors
without `environmentIndependent`; an invocation whose resolution is unresolved
therefore defers.
