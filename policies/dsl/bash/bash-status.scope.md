# `bash-status` policy scope

## Intent

Automatically authorize the direct Bash status builtins `:`, `true`, and
`false` when their invocation has no command-specific effect beyond producing
the status defined by Bash.

## Protected action and asset

The protected boundary is automatic authorization of one modeled direct Bash
builtin invocation. This policy does not authorize filesystem access, nested
command execution, environment mutation, or commands in a later tool call.
File opens caused by redirections are independently decided by the harness file
permission system.

## In scope

The policy permits exactly these forms:

- The immediate, unqualified executable spelling is `:`, `true`, or `false`.
- Immediate lookup resolves that spelling to a Bash builtin, not a shell
  function or external executable.
- There are no command-prefix assignments.
- Every operand is statically resolved. Any number of operands, including zero,
  is accepted because these builtin operands do not change the builtin's
  command-specific effect.
- Supported redirections are in scope. Their owned file-open effects remain
  separately subject to harness permission checks.

For example, `true`, `true -q arbitrary`, `: note > ./note.txt`, and
`false one two` are equivalent with respect to this policy's command-level
authorization.

## Out of scope and threat-model exclusions

This policy defers path-qualified spellings, function shadowing, unresolved
operands, prefix assignments, and every executable outside the three listed
builtins. It also does not authorize a command substitution or other nested
command that produced an operand; each reachable modeled invocation needs its
own policy decision.

The policy does not attempt to defend against adversarial shell-language
bypasses. It relies on the Bash parser/walker to emit complete invocation,
execution-target, operand-resolution, and redirection facts.

## Assumptions and non-goals

The policy assumes Bash's direct `:`, `true`, and `false` builtins do not give
their operands command-specific side effects after expansion. It does not
guarantee a particular shell-control-flow result: `true` succeeds and `false`
fails by design, and callers may use those statuses in surrounding shell
syntax. It does not authorize the path named by a redirection.

Each shell tool call has a fresh Bash process. Shell-local state can still
affect later commands in the same submitted source, which are outside this
policy unless independently covered.

## Expected outcomes

- **permit:** every exact in-scope invocation returns `allow` from this
  permission policy. The complete request is automatically allowed only if all
  other modeled invocations and all harness file checks allow it.
- **defer:** every form outside the grammar returns `defer`, including unknown
  operands, assignments, non-builtin resolution, and path-qualified spellings.
  A harness prompt or unknown result for a redirected file also remains
  deferred at request finalization.
- **deny:** this policy has no deny rule. Independent guard policies can still
  deny a command or a harness file access.

Because an `allow` requires a proven Bash builtin rather than an unresolved
external target, this policy deliberately leaves its executable selectors
without `environmentIndependent`; an invocation whose resolution is unresolved
therefore defers.
