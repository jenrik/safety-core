# `bun-test` project policy scope

## Intent

Automatically authorize `bun test` runs of this project's test suite,
including selecting specific test files with project-relative patterns, so an
agent working in this repository can run the documented test loop without a
permission prompt.

## Protected action and asset

The protected action is automatic authorization of one modeled `bun test`
invocation. The asset behind the decision is code execution authority on the
operator's machine: a Bun test run executes every discovered test file, with
arbitrary side effects, under the agent's ambient authority.

The secondary protected boundary is *where the selection may point*. Bun runs
an explicitly named test file even when it lives outside the working directory,
so the policy confines selection words to project-relative spellings.

## Tested version and in-scope grammar

The inventory is pinned to the installed and tested `bun 1.3.13`. Permitted
grammar:

```text
bun test [reviewed flag]* [project-relative word]*
```

- The immediate, unqualified executable spelling must be exactly `bun`
  (`isDirectExecutable("bun")`), the immediate target must be
  `external-path`, and there must be no command-prefix assignments.
- The first operand word is exactly `test` (case-sensitive).
- Reviewed flags are recognized only after the `test` subcommand, between or
  after selection words. A flag spelled before the subcommand (`bun --coverage
  test`) defers; Bun 1.3.13 does accept some of those spellings, so this is a
  deliberate deferral (a prompt, never an authorization) rather than an
  authority claim.
- Every non-flag word must satisfy all of: it does not start with `-`, `/`, or
  `~`; it is not exactly `..`; it does not contain the substring `../`; and it
  does not end with `/..`. Words with a known empty value (for example an unset
  variable in a verified environment) are accepted; Bun treats an empty pattern
  as "all tests".
- The standalone word `--` never permits. An invocation whose argv contains the
  exact word `--` anywhere defers (see below); `--` is neither an accepted
  operand nor a modeled terminator.
- The allow is emitted only at end of argv, so an unreviewed word can never be
  accepted as a suffix.

The reviewed flag inventory (forms as declared in the policy) is:

| Flags | Value | Accepted forms |
| --- | --- | --- |
| `-t`, `--test-name-pattern` | required | separate, attached short, `--flag=value` |
| `--timeout`, `--retry`, `--rerun-each`, `--max-concurrency`, `--parallel-delay`, `--seed`, `--shard`, `--path-ignore-patterns`, `--coverage-reporter` | required | separate, `--flag=value` |
| `--bail`, `--changed`, `--parallel` | optional | bare or `--flag=value` |
| `--coverage`, `--no-coverage`, `--only`, `--todo`, `--pass-with-no-tests`, `--concurrent`, `--randomize`, `--isolate`, `--dots`, `--only-failures` | none | bare |

The inventory is limited to switches that only change test selection, ordering,
concurrency, or reporting. Flag values are not validated by the policy, because
none of the reviewed value flags names a module, output path, working
directory, configuration file, or environment file, and because Bun's own
parser consumes the separate value token in every reviewed case: verified
against Bun 1.3.13 with `-t/--test-name-pattern`, `--timeout`, `--retry`,
`--rerun-each`, `--max-concurrency`, `--parallel-delay`, `--seed`, `--shard`,
`--path-ignore-patterns`, and `--coverage-reporter`, where the following token is
never treated as a positional pattern. `--bail`, `--changed`, and `--parallel`
consume a value only in the `--flag=value` form, so `bun test --bail 2` is
modeled as bare `--bail` plus the selection word `2`, exactly as Bun 1.3.13
treats it.

One ambiguous shape was measured directly against Bun 1.3.13 after adversarial
review:

- **`-t` does not cluster short flags.** `bun test -tu` runs only a test named
  `u` (the attached value form); it does not apply `-u`/`--update-snapshots`,
  which would have run every test. `bun test -t -u` and `bun test -t-u` supply
  `-u` as the name pattern. This is why `-t` declares `attachedShort` and no
  cluster form.

### `--` defers

The policy does not model an option terminator. Bun recognizes `--` as the flag
terminator only in command-line position; in a required-value position Bun
instead consumes `--` as that option's value. Verified against Bun 1.3.13:
`bun test --timeout -- tests/inside.test.ts` fails with `Invalid timeout:
"--"`, and `bun test -t -- --seed /tmp/evil.test.ts` consumes `--` as the
pattern and `/tmp/evil.test.ts` as the seed. Because the same token means
different things by position, and because Bun treats a reviewed flag spelling
after the terminator as a positional test path (`bun test -- --timeout
/tmp/evil.test.ts` executes the outside file), the policy refuses the whole
family rather than tracking the position.

The allow is a positive proof over raw argv. The `noTerminator` `argv` fold is
an `all` fold whose predicate is `not equals(fold.item, "--")`; an `all` fold is
`true` only when every word is known and non-`--`, and is `UNKNOWN` when any
word is unknown. The authored allow terminal requires both
`atEndOfArguments()` and `fold.noTerminator`, and the `selection` state's `end`
is `defer`, so `allow` is reachable only through that proven terminal.
Consequences:

- `bun test --`, `bun test -- tests/example.test.ts`, `bun test -- --timeout
  /tmp/evil.test.ts`, `bun test -t -- --seed /tmp/evil.test.ts`, and
  `bun test --timeout -- tests/inside.test.ts` defer.
- A `--` that an option would otherwise consume as its value is caught, because
  the fold scans raw argv rather than the machine's consumed sequence; the
  result does not depend on option-consumption order.
- An **unknown** argv word defers anywhere, including in a required-value
  position. A required option consumes its next word unconditionally, but the
  `all` fold stays `UNKNOWN` when any word is unknown, so the allow proof fails
  and `end` defers. This closes the expansion gap in which a value could expand
  to a standalone `--` plus an outside test path (`bun test -t ${FLAGS}`,
  `bun test -t "$@"`, `bun test -t "${!N}"`).
- A known-empty word (a verified unset variable) remains allowed, matching
  Bun's "empty pattern means all tests".

The same separate-value measurement covers every required-value flag: for
`-t`, `--test-name-pattern`, `--timeout`, `--retry`, `--rerun-each`,
`--max-concurrency`, `--parallel-delay`, `--seed`, `--shard`,
`--path-ignore-patterns`, and `--coverage-reporter`, `bun test FLAG
/tmp/evil.test.ts` consumes `/tmp/evil.test.ts` as the flag value and executes
no outside file.

Evidence that the selection rule is required: from a project working directory,
`bun test /tmp/evil.test.ts`, `bun test ../evil.test.ts`, and
`bun test -- --timeout /tmp/evil.test.ts` all executed a test file outside the
project (verified with Bun 1.3.13), while `bun test ""` and `bun test tests`
behaved as ordinary selection.

## Out of scope and threat-model exclusions

Every form below returns `defer`, leaving the native harness prompt in place.

- **Project-escaping selection**: absolute paths (`/tmp/x.test.ts`), `..`
  components (`..`, `../x`, `a/../b`, `a/..`), and `~` spellings. This is a
  lexical rule; see the assumptions for its limits.
- **Snapshot updates** (`-u`, `--update-snapshots`): rewriting the committed
  test oracle is a reviewed human action, not an automatic one. Running
  `bun test` to inspect failures remains covered.
- **Code loading** (`--preload`, `--require`, `--import`, `-r`): imports a
  module that is not one of the executed test files.
- **Relocation and configuration** (`--cwd`, `-c`/`--config`,
  `--env-file`, `--no-env-file`): changing the working directory, Bun
  configuration, or environment file changes what the run means and where it
  executes.
- **Output paths** (`--coverage-dir`, `--reporter`, `--reporter-outfile`):
  writes reporter or coverage output to a chosen path. `--coverage` and
  `--coverage-reporter` remain covered because their output stays under the
  project default directory.
- **Dependency installation and network resolution** (`--install`, `-i`,
  `--prefer-latest`, `--prefer-offline`): dependency state is not this
  policy's protected action.
- **Inline evaluation** (`-e`/`--eval`, `-p`/`--print`) and **debugger or
  profiler switches** (`--inspect*`, `--cpu-prof*`, `--heap-prof*`).
- **Non-terminating modes** (`--watch`, `--hot`).
- **Internal and unknown switches** (`--test-worker`, any unlisted flag or
  boolean assignment such as `--coverage=false`). Unreviewed words defer
  rather than being treated as harmless.
- **Flags before the subcommand**: a reviewed flag spelled before `test`
  (`bun --coverage test`) defers, because options are available only after the
  subcommand.
- **The standalone `--` word** anywhere in argv, including the terminator form
  (`bun test -- --timeout tests/a.test.ts`) and a `--` consumed as an option
  value (`bun test -t -- --seed tests/a.test.ts`).
- **Other subcommands and runners** (`bun run test`, `bun install`, `bunx`,
  `node`). `bun run test` is owned by the project `bun-run` policy, which
  itself defers the `test` runner subcommand.
- **`command bun test`**: the outer `command` builtin needs its own policy;
  this policy permits only the nested `bun` child.
- **Function shadowing** (`BASH_FUNC_bun%%`), path-qualified `bun` spellings,
  and unresolved targets.

The standalone `--` word is an explicit exclusion: an invocation containing it
anywhere in argv defers. The policy declares no terminator state, so there is
no post-terminator region to authorize and no position-dependent `--` handling
to reconcile with Bun. The measured Bun behavior that motivates refusing both
the terminator and value-position spellings is recorded under the in-scope
grammar above.

## Assumptions and non-goals

The confinement rule is lexical only. The policy cannot resolve paths,
symlinks, or globs: a project-relative pattern that Bun resolves through a
symlink pointing outside the project, a test file that `cd`s elsewhere, or a
pattern that matches a file outside the working tree is not detected. It also
cannot prove that the selected files are test files, or that the executed test
code does not write, spawn, or read anything; test code is trusted project code
with arbitrary side effects, and this policy deliberately grants that.

The policy assumes the DCRM-supplied facts (immediate target, executable
spelling, complete or explicitly unknown operand resolution, prefix
assignments) are complete, and that incomplete values defer. The EOF allow
proof enforces the last point directly: because allow requires an `all` fold
over every argv word, an unknown word cannot be authorized even when an option
matcher would have consumed it as a value. It assumes the reviewed Bun flag
inventory of 1.3.13 and the measured short-flag non-clustering behavior
described above; a Bun upgrade that changes a flag's meaning or short-flag
parsing requires re-review. It deliberately assumes no `--` semantics: every
`--` word defers regardless of Bun's position-dependent handling, so a Bun
change to `--` cannot widen this policy.

It is not a sandbox, not a coverage, dependency, or output-path policy, not a
test-file allowlist, and not a guard. It does not deny anything.

These policy bytes live inside the repository the agent works in (a project
policy under `.safety-core/`), which is acceptable only under the documented
non-adversarial threat model; OpenCode and Pi retain the policy object loaded
at start-up until restart or an explicit policy reload.

## Expected outcomes

- **permit:** `bun test` with reviewed flags and project-relative selection
  returns `allow`. The complete request is automatically allowed only when
  every other modeled invocation and harness file check also allows.
- **defer:** any invocation containing the standalone `--` word or an unknown
  argv word, escaping selection words, unreviewed flags, other subcommands,
  prefix assignments, path-qualified spellings, function shadowing, unknown
  pattern values, and unresolved operands return `defer`. A harness prompt or
  unknown file-permission result also keeps the request deferred.
- **deny:** this policy has no deny rule. Independent guard policies and harness
  file checks can still deny, and that denial dominates.

The v1 DCRM grammar only permits `reason` and `suggestion` templates on
`allow` and `deny` terminals, so the per-exclusion reasons above are recorded
here rather than being rendered for a `defer` outcome.
