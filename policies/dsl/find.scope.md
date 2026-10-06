# `find` policy scope

## Intent

Automatically permit GNU `find` traversal and output when every argument is a
read-only inspection form, while deferring any argument that executes a
command, deletes a filesystem entry, or writes to a file. The policy also
refuses to treat Bash code named `find` as the external GNU program.

## Protected action and asset

The protected actions are command execution, filesystem deletion, and
arbitrary file writes that `find` can perform through its expression
actions. The protected boundary is immediate Bash command
resolution: a basename match must not authorize a local or inherited Bash
function that shadows GNU `find`.

## In scope

This permission policy selects invocation events whose resolved executable
basename is exactly case-sensitive `find`. It returns `allow` only if
immediate Bash lookup resolves the invocation to `external-path`, the cursor
is at the end of argv, and no deferred action token was seen at any position.

All read-only `find` argument forms are in scope and equivalent to this
policy, in any order and at any position within the expression. This includes
zero or more path operands, operators (`(`, `)`, `!`, `-not`, `-a`,
`-and`, `-o`, `-or`, `,`), normal and positional options
(`-depth`, `-maxdepth`, `-mindepth`, `-mount`, `-noleaf`, `-xdev`,
`-ignore_readdir_race`, `-noignore_readdir_race`, `-daystart`,
`-follow`, `-warn`, `-nowarn`, `-regextype`, `-D`, `-O`,
`-files0-from`), tests
(`-name`, `-iname`, `-path`, `-type`, `-size`, `-perm`, `-newer`,
`-newerXY`, `-anewer`, `-cnewer`, `-empty`, `-readable`, `-writable`,
`-executable`, `-fstype`, `-false`, `-true`, and the remaining GNU 4.11
tests), stdout actions (`-print`, `-print0`, `-printf`, `-ls`), and
traversal control (`-prune`, `-quit`). `--help`, `-version`, and
`--version` are also in scope.

`-files0-from FILE` and `-files0-from -` are deliberately permitted by
operator decision, even though they read a starting-point list from an
arbitrary file or standard input. This is an accepted risk: the policy treats
the read as an ordinary `find` input, and GNU `find` can echo the file's
bytes back as path names. The file-content disclosure risk is recorded here
rather than blocked.

Both an unqualified external `find` and a path-qualified external executable
whose basename is `find` are selected. `command find` is in scope when Bash
models its immediate target as `external-path`; it intentionally bypasses a
shell function and invokes the external command.

Prefix assignments, pipelines, standard-input producers, redirections, and
surrounding shell constructs are not restricted by this argv policy. Every
separately modeled command and every shell-owned file access retains its own
authorization decision.

## Deferred in scope

The policy defers when any argv word, at any position, is one of the following
exact, case-sensitive primaries:

- **Executes a command:** `-exec`, `-execdir`, `-ok`, `-okdir`. Both the
  `;` terminator and the GNU batched `{} +` terminator are covered because
  the action token itself is deferred. `-ok` and `-okdir` additionally
  block on an interactive prompt and would not terminate non-interactively.
- **Deletes filesystem entries:** `-delete`.
- **Writes to a named file:** `-fprint`, `-fprint0`, `-fprintf`,
  `-fls`. These take an output path as an argv operand rather than as a shell
  redirect, so the harness file-permission layer does not separately see the
  write.

Deferral is fail-closed: the token is matched wherever it appears, including
when it is the value of an unrelated primary (for example
`find . -name -exec`). That over-defer is a documented false positive; the
value position is not parsed.

## Out of scope and threat-model exclusions

An invocation whose immediate target is `shell-function` is explicitly denied,
whether the `find` function was declared locally in the Bash source or
inherited from the environment. The denial applies even if that function would
eventually invoke external `find`, because this policy does not inspect or
authorize arbitrary Bash function bodies.

Selected invocations resolving to a Bash builtin or to an unresolved target
defer. Basenames other than exact lowercase `find` are not selected. Bash
alias definitions and expansion are outside scope because the analyzer does
not model them; if expansion yields a selected external `find` invocation,
that resulting event is assessed normally.

This policy does not validate GNU option arity, establish that path operands
exist, inspect the contents of traversed files, limit output volume or
traversal cost, or establish command success. It does not authorize nested
command substitutions, pipeline peers, process substitutions, redirection
effects, or other commands in the source. Replacing a selected executable,
manipulating `PATH`, or deliberately bypassing this policy through another
program is outside the non-adversarial threat model.

The defer set is the complete mutating/executing action vocabulary of the
tested GNU findutils. A future `find` release that adds a new destructive,
executing, or file-writing primary would not be recognized by this policy;
the version must be re-pinned and the set re-reviewed on upgrade.

## Assumptions and non-goals

The policy assumes that an external executable selected by basename `find` is
GNU findutils `find` or a compatible implementation. The tested inventory is
the installed GNU findutils `4.11.0`. Basename selection is an
operator-requested convenience, not proof of executable identity or
provenance. The external-target check and explicit shell-function denial are
the complete modeled protection against Bash function shadowing.

This is not a path allowlist, content-validation, output-size, environment,
pipeline, or process-sandboxing policy. It intentionally accepts the risk that
read-only GNU `find` walks arbitrary operand paths and prints their names, and
that `-files0-from` can read and echo the contents of an arbitrary file or
standard input.

## Handler boundary

The native structural wrapper handler `findHandler`
(`src/bash/handlers/command-find.ts`) only extracts commands that a GNU
`find` expression can run: each `-exec`/`-execdir`/`-ok`/`-okdir` body
becomes a child invocation, and unresolved regions become opaque child
executions. The handler returns a neutral (safe) outcome for the `find`
invocation itself, so it neither permits nor blocks `find`; that decision
comes from this policy and any guard. The handler also uses GNU primary arity
so that an action-shaped operand (for example `find . -name -exec`) is not
reinterpreted as an action.

One guard exception remains inside the handler: a `-files0-from` operand that
names a protected secret path is denied as `secret-read`, matching the native
`xargs` arg-file and reader guards. Removing that guard from the handler
without an equivalent policy guard would permit reading a secret file list.

## Expected outcomes

- **permit:** every selected event with immediate target `external-path`,
  argv end reached, and no deferred action token returns `allow`. A full
  request is automatically allowed only when all other modeled commands and
  file-access checks also allow and no guard denies it.
- **defer:** any of the deferred action tokens at any position; selected events
  whose target is a builtin or unresolved; and any incomplete transition.
- **deny:** a selected event whose immediate target is `shell-function`
  returns `deny` with guidance to invoke external GNU `find` (for example,
  `command find`) or remove the function. This denial dominates any permit
  from another policy for the same event.

Because an `allow` requires a proven external path, this policy deliberately
leaves its executable selector without `environmentIndependent`; an invocation
whose executable resolution is unresolved therefore defers.
