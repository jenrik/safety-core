# `env-command` policy scope

## Intent

Permit `env` only when it structurally has a direct child command. This lets an
agent use `env` as a transparent environment wrapper without automatically
authorizing the environment-listing behavior of `env` with no command.

## Protected action and asset

The protected action is automatic authorization of the outer modeled `env`
invocation. The protected asset is the inherited or modified process
command. This policy does not authorize either the command that `env` launches
or any file access caused by redirection; those are separate modeled effects
and require their own policy or harness decisions.

## In scope

This permission policy selects only modeled invocation events whose executable
basename is `env`, and permits a direct, unqualified external `env` executable
when its argv contains a direct, non-empty child command after supported GNU
`env` modifiers and `NAME=VALUE` assignments. Modifiers and the option
terminator must precede the first assignment operand:

- `-`, `-i`, and `--ignore-environment`;
- `-u NAME`, `-uNAME`, `--unset NAME`, and `--unset=NAME`;
- `-C DIR`, `-CDIR`, `--chdir DIR`, and `--chdir=DIR`;
- `-a ARG0`, `-aARG0`, `--argv0 ARG0`, and `--argv0=ARG0`;
- `-0`/`--null`, `-v`/`--debug`, and `--list-signal-handling`;
- `--block-signal`, `--default-signal`, and `--ignore-signal`, each with an
  optional `=SIGNAL` value; and
- the `--` option terminator, followed by zero or more `NAME=VALUE` assignments
  and then a non-empty child command, including a command spelling that begins
  with `-`.

The short forms above also accept natural short clusters: `-i`, `-0`, and `-v`
may be combined in any order, and a cluster may end in `-u`, `-C`, or `-a`
with either its attached value or its next argv word as that option's value.
Examples include `env -iv MODE=test tool`, `env -iuOLD tool`, and `env -iC
/tmp tool`.

The policy recognizes GNU `env` assignments structurally: while scanning
assignment operands, every operand that contains `=` is an assignment, including
names that a shell would not accept as an identifier (for example, `A-B=y`,
`1X=y`, and `=y`). After `--` or the first assignment, the same rule applies
before child-command detection, including an assignment spelling such as
`--unset=OLD`. It accepts arbitrary assigned values and arbitrary arguments
after the first child-command word.
Once the first assignment is seen, GNU `env` does not recognize more modifiers:
a later `--`, `-`, or option-looking word is the child command. Therefore
`env MODE=test tool arg`, `env -i MODE=test tool`, `env
--unset=OLD -- MODE=test tool`, and `env -u OLD -C /tmp tool` are equivalent in
scope, while `env MODE=test -i tool` has `-i` as its child command.

## Out of scope and threat-model exclusions

Every invocation without a direct child command defers, including `env`, `env
MODE=test`, `env A-B=y`, `env -u OLD`, `env --null`, `env --`, and `env --
MODE=test`. This is the boundary that prevents automatic approval of
environment dumps.

The policy also defers unsupported or malformed modifiers, long-option
abbreviations, `--help`, `--version`, path-qualified `env`, unresolved command
words, and an empty child-command word. An inherited or locally defined Bash
function named `env` is not an `env` executable: the walker records a
`shadowed-env-function` execution gap before body analysis. The aggregate
analysis defers that gap independently; this policy does not select or
authorize function calls.
`-S`/`--split-string` deliberately defers: it embeds another argv grammar, and
an assignment-only or whitespace-only split string would still make `env` dump
its environment. Short-option clusters not represented by the declared option
forms, including every cluster containing `-S`, also defer.

Aliases outside the modeled direct executable spelling, alternate environment
printing utilities (`printenv`, shell `export -p`, or `set`), and deliberate
attempts to evade the policy by choosing another program or transport are
outside the non-adversarial threat model. This policy does not validate the
child command, its arguments, signal semantics, `PATH` resolution, output, or
the actual success of GNU `env`.

## Assumptions and non-goals

The Bash walker is assumed to emit complete outer `env` and child-invocation
events using the documented wrapper grammar. The policy's assignment scanner
matches GNU `env` assignment syntax, not shell prefix assignments. It is not a
general environment-redaction policy and cannot prevent a separately
authorized child command from intentionally printing its own environment.

This policy intentionally does not reproduce `env -S` parsing in the DSL.
Deferring that form is a conservative non-goal required to keep the no-dump
guarantee structural rather than dependent on unmodeled string parsing.

## Expected outcomes

- **permit:** a direct, unshadowed `env` invocation in the in-scope grammar,
  with a non-empty direct child command, returns `allow` for the outer `env`
  event. The complete request is automatically allowed only if the child event,
  every other event, and any file-access check are independently allowed.
- **defer:** every selected no-command, malformed, unresolved, excluded, or
  unsupported `env` form returns `defer` from this policy and remains
  prompt-gated unless another policy covers that event. In particular, all
  environment-printing no-command forms defer. A shadowed `env` function call
  is outside this policy's selector and instead defers through its execution
  gap.
- **deny:** this permission policy has no deny rule. A separate guard policy
  may still deny the request, and that deny dominates this policy's allow.
