# `timeout` policy scope

## Intent

Permit GNU `timeout` as a transparent execution wrapper after structurally
locating its own option operands, duration operand, and direct child-command
boundary. The policy does not inspect or authorize the child command.

## Protected action and asset

The protected action is automatic authorization of the outer modeled `timeout`
invocation. The protected asset is the permission boundary between `timeout`'s
own operands and the argv of the program that it launches. The child command,
its arguments, effects, and all file accesses are separate modeled effects and
require their own policy or harness decisions.

## In scope

This permission policy selects modeled invocation events whose executable
basename is `timeout`. It permits an invocation only when Bash resolved that
event to an external executable, rather than an inherited Bash function, and
the wrapper has this GNU coreutils 9.11 grammar:

```text
timeout [MODIFIER ...] [--] DURATION COMMAND [ARG ...]
```

`MODIFIER`s must appear before `DURATION`. They may be repeated and ordered
arbitrarily. The exact accepted spellings are:

- `-f`/`--foreground`, `-p`/`--preserve-status`, and `-v`/`--verbose`;
- `-k DURATION`, `-kDURATION`, `--kill-after DURATION`, and
  `--kill-after=DURATION`;
- `-s SIGNAL`, `-sSIGNAL`, `--signal SIGNAL`, and `--signal=SIGNAL`; and
- natural short-option clusters of `f`, `p`, and `v`, optionally ending in `k`
  or `s` with its attached value or taking its value from the next argv word.

The optional `--` is a timeout option terminator. Its immediately following
word is `DURATION`, even if that word starts with `-`. Without `--`, an
unrecognized hyphen-leading word defers rather than being treated as a
duration. `DURATION` and `COMMAND` must each be known and non-empty.
`-k`/`--kill-after` and `-s`/`--signal` must each have a known, non-empty
supplied value. All argv words after `COMMAND` are child-command argv and are
intentionally not interpreted by this policy.

The policy admits any non-empty duration, kill-after value, and signal value;
it does not impose a time limit or signal allowlist. GNU coreutils owns
semantic parsing of those operands. This includes its documented floating-point
duration syntax and optional `s`, `m`, `h`, and `d` suffixes, including `0`
which disables the associated timeout.

Both an ordinary `timeout` command spelling and a path-qualified external
executable whose basename is `timeout` are selected. The policy requires the
modeled execution target to be `external-path` and explicitly rejects an
inherited Bash function named `timeout`.

## Out of scope and threat-model exclusions

The policy defers missing or empty duration/child operands, unknown options,
unsupported option forms, unsupported short-cluster contents, and every long
option abbreviation, even where a particular GNU getopt implementation might
accept it. It also defers missing, empty, or unresolved
`-k`/`--kill-after` and `-s`/`--signal` values. `--help` and `--version` are
recognized as terminal informational modes and defer, including if trailing
words follow them. A function named `timeout` is outside the selector's
permitted execution target and this policy does not authorize its function body.

The policy deliberately does not validate duration, signal, or kill-after
syntax beyond their positional boundary. A malformed value can receive the
outer wrapper's permit only if it is non-empty and placed in an in-scope form.
This relies on compatible GNU `timeout` behavior: invalid operands cause
`timeout` itself to fail before it launches `COMMAND`, rather than loading a
file or evaluating a program. The policy does not establish that property for
an arbitrary executable merely named `timeout`.

It does not validate the child command, child argv, resolution, timeout
expiration, process-tree behavior, signal delivery, exit status, stdout/stderr,
environment changes, redirections, or actual command success. In particular,
`--foreground` can leave children of `COMMAND` outside timeout's process-group
control, and this policy does not restrict that behavior. The engine is
expected to model and independently authorize the nested command.

Alternate timeout implementations, other executable basenames (such as
`gtimeout`), aliases not expanded to a selected `timeout` invocation, and
deliberate bypass attempts through another executable or transport are outside
the non-adversarial threat model.

## Assumptions and non-goals

The grammar is pinned to the installed GNU coreutils 9.11 `timeout` help
inventory. The policy assumes a selected external program named `timeout` is
GNU coreutils 9.11 or a compatible implementation, especially for invalid
operand handling. It deliberately uses basename selection to support both
ordinary and path-qualified command spellings, so it is not a binary-identity
or filesystem-provenance policy.

This is not a duration-limit, signal-safety, process-sandboxing, or
child-command permission policy. It introduces no maximum duration: all
non-empty duration operands are treated equally after their structural position
is established.

## Expected outcomes

- **permit:** a selected external `timeout` event with only the exact in-scope
  pre-duration modifiers, a known non-empty duration, and a known non-empty
  direct child command returns `allow` for the outer wrapper. The complete
  request is automatically allowed only if the separately modeled child event,
  every other event, and every file-access check are independently allowed.
- **defer:** every selected invocation with a missing, empty, unresolved,
  unsupported, malformed-at-the-grammar-level, or informational form returns
  `defer`. This includes invalid long-option spellings; omitted, empty, or
  unresolved `-k`/`-s` values; unrecognized clusters; no child command; and
  `--help`/`--version`. Semantically malformed but known non-empty duration,
  kill-after, or signal values are an explicit exception described above: their
  outer wrapper can permit while compatible GNU `timeout` is expected to fail
  before child execution.
- **deny:** this permission policy has no deny rule. A separate guard policy
  may still deny the wrapper, child, or file access, and that deny dominates
  this policy's permit.
