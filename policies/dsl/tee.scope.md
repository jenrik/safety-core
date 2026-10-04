# `tee` policy scope

## Intent

Automatically permit GNU `tee` without restricting its output destinations,
while withholding automatic authorization when Bash resolves `tee` to a
function.

## Protected action and asset

The protected action is automatic authorization of one selected modeled `tee`
invocation. The protected boundary is immediate Bash command resolution: a
basename match must not automatically authorize a local or inherited Bash
function that shadows GNU `tee`. Destination paths are deliberately not
protected by this policy; GNU `tee` may write any file path supplied as an
operand.

## In scope

This permission policy selects invocation events whose resolved executable
basename is exactly case-sensitive `tee`. It returns `allow` only if immediate
Bash lookup resolves the invocation to `external-path`.

All argv forms are in scope and equivalent to this policy. This includes GNU
`tee [OPTION]... [FILE]...` forms; `-a`/`--append`, `-i`/`--ignore-interrupts`,
`-p`, `--output-error[=MODE]`, `--`, `--help`, and `--version`; repeated,
reordered, malformed, empty, unknown, or binding-derived arguments; and any
zero or more file operands. File operands may name any path. The policy does
not parse options, operands, `--`, or GNU `tee`'s output-error modes.

Both an unqualified `tee` in Bash's external-path lookup domain and a
path-qualified executable whose basename is `tee` are selected. This target
classification does not prove that a PATH lookup found a file: an event with
an incomplete, not-found executable identity can still be `external-path` and
is permitted, because it cannot execute successfully.

For `command tee`, the core first models the `command` builtin and then models
the transparent-wrapper child `tee`. This policy selects and permits the child
when its immediate target is `external-path`; it does not select or permit the
outer `command` builtin. Therefore a configuration containing only this policy
leaves the complete `command tee` source deferred, even though its nested `tee`
event permits. A separately enabled policy must authorize `command` for the
complete source to permit.

Prefix assignments, pipelines, standard-input producers, redirections, and
surrounding shell constructs are not restricted by this command's argv policy.
Every separately modeled command and every shell-owned file access retains its
own authorization decision. In particular, harness file permissions govern
redirection targets independently; this policy's file-operand allowance does
not authorize an attached shell redirection.

## Out of scope and threat-model exclusions

An invocation whose immediate target is `shell-function` explicitly defers,
whether the `tee` function was declared locally in the Bash source or inherited
from the environment. The defer applies even if that function would eventually
invoke external `tee`, because this policy intentionally does not inspect or
automatically authorize arbitrary Bash function bodies.

Selected invocations resolving to a Bash builtin or to an unresolved target
defer. Basenames other than exact lowercase `tee`, including `gtee`, `tee.exe`,
and `teed`, are not selected. Bash alias definitions and expansion are outside
scope because the analyzer does not model them; if expansion yields a selected
external `tee` invocation, that resulting event is assessed normally.

This policy does not validate GNU option syntax, read standard input, inspect
the bytes that `tee` writes, restrict file paths, establish whether a file
exists, or determine command success. It does not authorize nested command
substitutions, pipeline peers, process substitutions, redirection effects, or
other commands in the source. Replacing a selected executable, manipulating
`PATH`, or deliberately bypassing this policy through another program is
outside the non-adversarial threat model.

## Assumptions and non-goals

The policy assumes that a successfully executed external program selected by
basename `tee` is GNU coreutils `tee` or a compatible implementation. Basename
selection is an operator-requested convenience, not proof of executable
identity, provenance, or integrity. The external-target check and explicit
shell-function defer are the complete modeled protection against automatic
authorization of Bash function shadowing.

This is not a file-path allowlist, content-validation, output-size,
append-versus-overwrite, environment, pipeline, or process-sandboxing policy.
It intentionally accepts the risk that GNU `tee` writes arbitrary data to
arbitrary operand paths.

## Expected outcomes

- **permit:** every selected event with immediate target `external-path`
  returns `allow`, regardless of arguments, file operands, or invocation
  context, including an `external-path` event with an incomplete not-found
  executable identity. A full request is automatically allowed only when all
  other modeled commands and file-access checks also allow and no guard denies
  it.
- **defer:** selected events whose target is `shell-function`, a builtin, or
  unresolved return `defer`; unselected basenames receive no decision from this
  policy. This includes the outer `command` event in `command tee` when no
  separate command policy is enabled. Harness prompts, unknown file checks, and
  independent nested-command decisions can also prevent final automatic
  approval.
- **deny:** this policy has no deny rule. Independent guard policies and
  harness file-access checks can still deny a selected invocation or its
  surrounding effects, and that denial dominates this policy's permit.
