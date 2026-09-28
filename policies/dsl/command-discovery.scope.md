# `command-discovery` policy scope

## Intent

Permit one narrowly defined, read-only Bash command-discovery operation without
a harness prompt: `command -v <name>`. This lets an agent determine the
resolution of one command name before it selects a separately authorized
command to run.

## Protected action and asset

The protected boundary is automatic authorization of the modeled `command`
invocation. This policy must not authorize execution through the `command`
builtin, command environment changes, or output redirection attached to that
invocation. It only authorizes the builtin's single-name lookup operation.

## In scope

The policy permits exactly an invocation with all of these properties:

- The executable is the direct, unqualified Bash builtin spelling `command`;
  it is not path-qualified and is not shadowed by an inherited executable
  function.
- There are no command-prefix assignments and no redirections.
- The argv is exactly `-v`, followed by one statically resolved, non-empty name
  that does not begin with `-`.

Thus `command -v helm` and `command -v git` are equivalent in scope. The name
may be a simple command name or a slash-containing command spelling, provided
it is statically resolved and meets the preceding rule; this policy does not
assert that the lookup succeeds or that the result names an executable file.

## Out of scope and threat-model exclusions

The following defer rather than inheriting this permission: `command -V`,
`command -p -v <name>`, clustered or reordered flags, `--`, empty, option-like,
unresolved, missing, or multiple names, path-qualified `command`, function
shadowing, prefix assignments, and every redirection.

Ordinary execution forms such as `command helm list` are explicitly outside
this lookup policy. The core models both the outer `command` invocation and
the nested `helm list` invocation. Automatic approval therefore requires a
permission policy that covers the outer form and another that covers the nested
form; this policy intentionally covers neither.

This scope excludes adversarial attempts to manipulate the shell, `PATH`, or
function state to misrepresent command resolution. It also excludes aliases,
other command-discovery builtins or utilities (`type`, `which`, and `builtin`),
and shell-specific behavior beyond the modeled direct Bash builtin.

## Assumptions and non-goals

The Bash parser and walker provide a complete, resolved direct invocation event
for the stated form, and the host's `command -v` operation itself performs no
target execution. This policy is not a guarantee that a discovered path is
safe, stable, present, executable, or later authorized. It is not a general
read-only policy and does not authorize execution, file reads, environment
mutation, or terminal output handling.

Two existing core-modeling limitations are explicitly excluded from this policy
scope and are tracked in [`docs/known-bugs.md`](../../docs/known-bugs.md):
complete environment snapshots do not currently normalize exported Bash
functions, and some standalone shell work can be absent from the policy event
stream. Accordingly, the policy's function-shadowing and redirection checks
apply to facts carried by its invocation event; they do not prove that the
entire Bash source lacks those omitted effects.

## Expected outcomes

- **permit:** the exact in-scope shape above yields `allow` from this
  permission policy. The combined request is automatically allowed only when
  every other reachable invocation is also covered and no guard denies it.
- **defer:** every form outside the grammar, including all forms listed as out
  of scope, yields `defer` from this policy and remains prompt-gated unless an
  independent policy covers that invocation. In particular, `command helm
  list` is not permitted by this policy.
- **deny:** this permission policy declares no deny rule. Independent guard
  policies retain their normal dominant ability to deny an invocation (for
  example, a protected-input guard); such a denial is outside this policy's
  lookup authorization decision.
