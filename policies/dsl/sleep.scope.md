# `sleep` policy scope

## Intent

Automatically permit GNU `sleep` invocations without inspecting their argv. GNU
`sleep` only waits or reports its own argument errors; it does not launch a
child command from its operands.

## Protected action and asset

The protected action is automatic authorization of the selected modeled
`sleep` invocation. The protected boundary is command resolution: every known
basename match is permitted except a positively identified Bash function named
`sleep`; this is not executable-provenance enforcement.

## In scope

This permission policy selects modeled invocation events whose executable
basename is exactly case-sensitive `sleep`. Its selector explicitly opts into
environment-independent permission coverage. It returns `allow` for every
selected immediate execution target except a positively identified Bash
`shell-function`: `external-path`, `builtin`, and `unresolved` are allowed.
An `unresolved` target is included deliberately when the initial environment
cannot establish whether `sleep` is shadowed.

All argv forms are in scope and equivalent to this policy, including zero or
multiple operands, GNU options (`-`/`--` spellings), `--`, malformed operands,
empty arguments, unknown or binding-derived arguments, and arbitrary argument
ordering. The policy intentionally does not parse GNU `sleep` options or
operands. Both unqualified `sleep` and path-qualified external executable
spellings ending in `/sleep` are selected; a matching builtin or unresolved
spelling is selected and permitted as well.

The policy imposes no independent restriction on prefix assignments,
redirections, pipelines, or surrounding shell constructs attached to the
selected invocation. Those are not argv parsing concerns: separately modeled
commands and every file-access permission check retain their own authorization
decisions.

## Out of scope and threat-model exclusions

A local or inherited Bash function named `sleep` returns `defer`; the policy
does not authorize that function's body, even if it would eventually run an
external `sleep`. Executable basenames other than the exact lowercase `sleep`
(including `gtimeout`, `usleep`, and `sleepy`) are not selected by this policy
and receive no decision from it.

Bash alias expansion is outside this policy because the analyzer does not model
alias definitions or expansion. Other waiting utilities, shell builtins, and
wrappers are also outside scope unless their analysis independently emits a
selected external `sleep` invocation.

The policy does not parse, validate, bound, or require a sleep duration;
whether GNU `sleep` succeeds, exits with an error, is interrupted, or waits for
an unbounded time is outside scope. It also does not permit command
substitutions or other modeled nested commands used to construct an argument;
they need separate coverage. Malicious replacement of a selected executable,
deliberate `PATH` manipulation, and bypasses through unrelated programs are
outside the non-adversarial threat model.

## Assumptions and non-goals

The policy assumes a selected non-function command whose basename is `sleep`
is GNU coreutils `sleep` or a compatible implementation that only implements
sleeping and argument reporting. Basename selection and environment-independent
coverage are deliberate at the operator's direction, so this is not a
filesystem-provenance, binary-identity, executable-resolution, or integrity
policy. A definite `shell-function` target is the sole modeled exception; an
unavailable environment can leave shadowing unresolved and therefore permits
the selected invocation by design.

This is not a time-limit, process-sandboxing, file-access, environment,
pipeline, or output-control policy. It does not guarantee completion, prevent
long waits, validate GNU-version-specific behavior, or authorize any nested
command or file effect.

## Expected outcomes

- **permit:** every selected event whose immediate target is not the definite
  `shell-function` target returns `allow`, regardless of argv or invocation
  context, including when its initial environment is unavailable. The entire
  request is automatically allowed only if all separately modeled commands and
  file accesses are independently allowed and no guard denies it.
- **defer:** a selected event whose target is the definite `shell-function`
  target returns `defer`. A non-selected basename receives no decision from
  this policy; absent another policy, that invocation remains prompt-gated.
- **deny:** this permission policy declares no deny rule. Independent guard or
  file-access policies can still deny a selected invocation or its surrounding
  effects, and that denial dominates this policy's permit.
