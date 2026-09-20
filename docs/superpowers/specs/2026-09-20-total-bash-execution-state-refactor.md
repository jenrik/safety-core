# Total Bash Execution State Refactor

## Purpose

Make Bash execution boundaries total and compositional so authorization cannot
lose shell state or a potentially executed child command. This is a structural
follow-up to the typed execution-target migration, not a collection of fixes
for individual command spellings.

## Why This Is Needed

The September 20 adversarial review found three High issues:

- non-isolated `time` and `eval` children preserve environment writes but lose
  function definitions;
- attached fish `-cSCRIPT` does not reach the mandatory fish-source denial; and
- attached Bash `exec -aNAME` forms do not expose the replacement command.

These have two shared root causes:

1. Child completion copies selected `Path` fields instead of propagating a
   complete abstract shell state.
2. A recognized child-launching handler can return a generic indeterminate
   outcome without representing the execution it failed to derive.

## Primary-Source Research Brief

Research for the September 20 follow-up corrections was completed before
implementation. The reviewed sources are:

- GNU Bash 5.3, [Pipelines](https://www.gnu.org/software/bash/manual/html_node/Pipelines.html),
  [Bourne Shell Builtins](https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html),
  [Bash POSIX Mode](https://www.gnu.org/software/bash/manual/html_node/Bash-POSIX-Mode.html),
  and [Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html);
- POSIX.1-2024, [Shell Command Language](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)
  and [`time`](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/time.html);
- GNU findutils' upstream manual source,
  [`doc/find.texi`](https://git.savannah.gnu.org/cgit/findutils.git/plain/doc/find.texi).
  The originally requested generated-manual URL,
  `https://www.gnu.org/software/findutils/manual/html_mono/find.html`, returned
  HTTP 404 during this review, so the official Savannah source is the retained
  primary citation.
- fish 4.9.3, [`fish` invocation](https://fishshell.com/docs/current/cmds/fish.html),
  and zsh 5.9.2, [Invocation](https://zsh.sourceforge.io/Doc/Release/Invocation.html),
  for the already-supported non-Bash command-source option forms.

The exact implementation rules derived from those sources are:

- Bash grammar defines a pipeline as `[time [-p]] [!] command1 ...`. The
  reserved word times the whole pipeline, `-p` selects the POSIX output format,
  and reserved-word timing can cover builtins, functions, compound commands,
  and pipelines. Therefore `-p` belongs to the `time_statement` CST and must
  never be repaired by deleting a projected command word. In Bash POSIX mode,
  `time` is not recognized as a reserved word when the next token begins with
  `-`; this parser does not currently carry invocation mode into CST parsing,
  so it intentionally models Bash's default grammar and records POSIX-mode
  parsing as a residual limitation.
- POSIX `time [-p] utility [argument ...]` is a utility invocation, not Bash's
  general pipeline construct. POSIX makes direct use with pipelines,
  redirections, following reserved words/control operators, special builtins,
  intrinsic utilities, or functions unspecified. This does not narrow Bash's
  documented reserved-word extension.
- POSIX `unset [-fv] name...` removes variables with `-v` and function
  definitions with `-f`. With neither option, a name denotes a variable and,
  if no such variable exists, removing a same-named function is unspecified.
  Unsetting an absent name is not an error; readonly variables cannot be unset;
  utility-syntax rules supply `--`. A removed function no longer wins function
  command search, so later resolution continues to intrinsic/builtin and PATH
  lookup.
- Bash `unset [-fnv] [name ...]` deterministically tries a variable first and,
  if none exists, a same-named function. `-f` selects functions, `-v` selects
  variables, and Bash rejects simultaneous `-f` and `-v`. `-n` unsets the
  nameref itself instead of its referent and has no effect with `-f`. Bash
  accepts clustered short options and `--`; readonly variables and readonly
  functions cannot be removed. The abstract model does not yet represent
  nameref or readonly-function attributes, so `-n`, conflicting/unsupported
  options, and dynamic option words conservatively taint complete shell state.
  A dynamic name under known `-f` invalidates function certainty without
  inventing an environment write; a dynamic variable/default name also taints
  environment facts.
- Bash invocation uses `-c string [argument ...]`: `-c` reads the first
  non-option argument as command source, the following argument becomes `$0`,
  and the remainder become positional parameters. Bash `-o`/`-O`, zsh
  `-o`/`+o`, and fish command/value options require values. Fish documents both
  `-c COMMAND` and `--command=COMMAND`; zsh documents `-c` taking the first
  following argument as command source and permits `-o` to be stacked with
  preceding short flags. Consequently a statically recognized value-taking
  option with an unresolved value retains its option identity and dynamic
  value. It is different from a missing argv element: a dynamic command-source
  value is explicit opaque execution (and fish remains hard-denied), while a
  genuinely absent required value is a malformed invocation.
- GNU `find` has the shape `find [file...] [expression]`. Starting points end
  when an expression argument is encountered; `--` cannot reliably disambiguate
  a starting point beginning with `-`. Expressions are primaries evaluated
  left-to-right and connected by `()`, `!`/`-not`, implicit or explicit
  `-a`/`-and`, `-o`/`-or`, and `,`. Many primaries consume their immediately
  following fixed number of argv elements. `-exec`, `-execdir`, `-ok`, and
  `-okdir` instead consume through an argv element exactly equal to `;`; the
  batched `-exec`/`-execdir` form ends only at `{} +`, with that sole `{}` at
  the end of the command template. `-files0-from` consumes one mandatory file
  argument and is mutually exclusive with command-line starting points.

The reviewed `find` parser subset is deliberately execution-oriented. It
recognizes GNU pre-path options `-H`, `-L`, `-P`, `-D`, and `-Olevel`; expression
operators; documented nullary options/tests/actions; documented one-argument
options/tests plus `-fprint`, `-fprint0`, `-fls`, and `-printf`; two-argument
`-fprintf`; one-argument `-files0-from`; and variable-arity `-exec`, `-execdir`,
`-ok`, and `-okdir`. Known fixed-arity operands are never reinterpreted as
actions. A dynamic word is harmless to action recognition when it occupies a
known operand slot, but at a starting-point/expression boundary, primary slot,
or variable-action body/terminator it creates an opaque repeated-execution
possibility. Concrete recognized sibling actions are still inspected, and a
concrete nested denial remains dominant. Unreviewed or malformed expression
forms cross the existing opaque approval boundary rather than being treated as
proof that no child executes.

## Target Model

### Complete abstract shell state

Group every caller-visible shell-state domain behind one abstraction. The
initial domains are environment bindings, function candidates, and missing
function facts. Future caller-visible domains must be added to this abstraction
and its composition operations, not propagated at individual call sites.

State composition has explicit semantics:

- current-scope sequential execution propagates the complete resulting state;
- subshell execution discards child state while retaining outcomes;
- alternative or repeated executions conservatively join complete states; and
- denials remain dominant under every composition.

Scope and process topology are separate facts. `time`, `eval`, `source`, and
current-shell builtins can have current scope even when their execution-target
kinds differ. Shell `-c`, external wrappers, pipelines, and `coproc` isolate
state according to their modeled semantics.

### Total structural execution results

A structural handler for a recognized executable must return one of:

- a terminal result proving that no child execution remains;
- an explicit execution plan containing every modeled child; or
- an explicit opaque execution with a redacted reason.

It must not silently drop a possible child by returning only `indeterminate`.
Opaque execution must cross an approval boundary rather than becoming an
evidence-free pass. Policy observers remain non-scheduling consumers; the
walker/runner owns execution scheduling and budgets.

Execution plans should state composition rather than relying on an unqualified
child array. Required composition kinds are single/sequential, alternatives,
and repeated execution. Keep the smallest representation that makes current
uses unambiguous.

### Shared declarative option grammar

Replace bespoke short-option loops for migrated handlers with a shared scanner
whose specification can express:

- no-argument and required-argument options;
- separate, attached, and equals value forms;
- short-option clustering, where a value-taking option consumes the remainder;
- `--`, stop-at-first-operand, and terminal options such as shell `-c`;
- exact versus explicitly enabled GNU unique-prefix long options; and
- dynamic, missing, conflicting, or unsupported forms as typed failures.

Shell interpreters and `exec` are the first consumers. The scanner must handle
fish's attached command source, Bash/zsh's source operand after the complete
short-option cluster, the documented best-effort zsh alias, mandatory fish
blocking, and separated/attached clustered `exec -a`.
Legacy child-launching handlers may migrate incrementally, but parse failures
must still produce explicit opaque execution.

### Symbolic words and deny-only preflight

Unknown expansion output is not predicted or executed. An unresolved word may
have an internal `SymbolicWordShape`: ordered literal/unknown fragments plus a
field cardinality of `one`, `one-or-more`, or `zero-or-more`. Exact words remain
`known`; consumers that do not understand shape still see the existing
`unknown` word and must remain conservative. Shapes are stored in a `WeakMap`,
not on the resolved word, so literal fragments cannot be copied by ordinary
serialization into outcomes, policy evidence, execution provenance,
diagnostics, or audit records.

Commands with retained substitutions use this order; commands without retained
work proceed directly to ordinary normalization and dispatch:

1. Normalize the command to an abstract word shape without running retained
   substitutions or predicting their output.
2. If the executable is not definitely a shell function, run its structural
   deny-only preflight. Preflight can return only concrete deny or continue; it
   cannot allow, defer, schedule children, or use partial knowledge as proof of
   safety.
3. On continue, walk retained command substitutions and other nested Bash
   statements under normal depth/work budgets.
4. Normalize again against the resulting shell state and perform ordinary
   builtin, structural-handler, observer, and typed-child dispatch.

The fish handler uses this preflight only when symbolic shape unambiguously
identifies `-c`/`--command` or `-C`/`--init-command`/`--init-cmd`. Separate,
attached, equals, and reviewed clustered forms are denied before their retained
substitutions consume work. Fully dynamic option identity continues to opaque
analysis. Normal dispatch retains the same denial for typed invocation children
and other routes that bypass CST preflight. `fish --version` and other ordinary
non-source invocations are not denied merely because the executable is fish.

Examples:

- quoted `fish --command "$(echo foo)"` normalizes to executable `fish`, a
  recognized command option, and unknown single-field source. The nested
  `echo` is walked only if preflight does not deny;
- `fish -c "$(unpredictable-command-output)"` likewise has unknown source. The
  analyzer never substitutes a guessed command output; and
- attached fish source such as `fish -c"$(producer)"` is one symbolic
  concatenated argv word with a literal `-c` prefix and unknown suffix, never a
  fabricated option argv plus source argv.

### Work-item admission

The walker's `maxWorkItems` is a total admission budget. A failed admission
records one redacted `max-work-items` failure and rejects that work, while every
work item already admitted to the internal LIFO agenda continues to drain. An
admitted concrete denial stops the walk and dominates the stored failure;
rejected work cannot fabricate a denial. Rejected parent continuations need not
complete because the stored global failure determines the result if admitted
work finds no denial. No rejection callbacks or secondary unbudgeted completion
queue are created.

`maxSteps` remains an execution budget with immediate-stop semantics. The outer
runner was checked separately: it already retains admission failure as evidence
while draining previously queued work, so no behavior change was required
there.

## Required Invariants

- Adding a shell-state domain cannot require edits at arbitrary child-boundary
  call sites.
- Current-scope children propagate every modeled state domain.
- Isolated children leak no modeled state domain.
- A recognized child-launching route always produces a plan or opaque execution.
- A concrete nested denial cannot be replaced by indeterminate or budget failure.
- Direct argv children are never serialized and reparsed as Bash source.
- Unknown data and reasons remain redacted; no raw source, argv, environment, or
  secret-bearing values enter policy evidence or provenance.
- Fish source hard-blocks until a dedicated parser exists. Zsh source uses the
  documented best-effort Bash parser alias until a matching parser exists.
- Symbolic word knowledge is monotonic: it may add denial or opacity, never
  automatic safety.
- Admission failure cannot erase a denial found by already-admitted work, and
  rejected work cannot create denial evidence.

## Migration Order

1. Introduce complete shell-state and centralized current/subshell/join
   operations; migrate child completion and branch joins.
2. Make recognized structural-handler results total, with opaque execution
   reaching the existing incomplete-analysis approval boundary.
3. Add the shared option grammar and migrate shell interpreters plus `exec`.
4. Add abstraction-level unit and property tests, then concrete policy
   regressions for the three reported High findings.
5. Update the broader typed-target design document to match the implemented
   contracts and record any deliberately deferred handler migrations.

## Verification Contract

Tests must include properties for current versus isolated state, conservative
state joins, option form and ordering equivalence, total child-launching
results, denial dominance, and bounded execution. Do not use skipped, todo, or
expected-failing tests.

Completion requires focused tests, full `bun test`, `nix flake check 'path:.'`,
`git diff --check`, and a fresh independent Critical/High adversarial review.
Present and discuss every adversarial finding with the operator before making
review-driven corrections. Do not modify or commit the unrelated `AGENTS.md`.

## Current Status

The typed-target migration, the first four review corrections, and this
structural follow-up are implemented but uncommitted. The implementation uses:

- `BashShellState` as the complete caller-visible state, with centralized
  environment replacement, function definition, current/subshell completion,
  and conservative joins;
- an opaque target carrying a closed, redacted `ExecutionUnknownReason`, with
  recognized structural parse failures normalized to that target before the
  existing incomplete-analysis approval boundary; walking an opaque target
  emits profile-independent analysis failure rather than policy-scoped defer;
- a declarative option scanner with typed failures and explicit exact versus
  GNU unique-prefix long-option policy; and
- the scanner as the shared parser for shell interpreter options and Bash
  `exec`, including fish attached command strings, Bash/zsh deferred command
  operands after complete clusters, and attached clustered `-a`.

The current `children` contract remains a conservatively joined collection.
A richer execution-plan algebra for explicit sequential, alternative, and
repeated composition is deliberately deferred because the current migrated
handlers do not require it to enforce totality, and changing every handler now
would add disproportionate churn. Any handler whose parser cannot establish a
child must emit opaque execution instead of relying on a plain indeterminate
outcome.

The follow-up parser and execution-boundary corrections are also implemented:

- a syntax failure carries an immutable `BashProgram` containing only complete,
  error-free root statements terminated before the malformed region; top-level
  and nested source analysis walk that prefix and then append redacted failure,
  with denial remaining dominant;
- direct `source` and `.` commands schedule opaque current-scope children.
  Current-scope opacity taints environment facts and invalidates certainty about
  prior function definitions without discarding their possible definitions;
- shell startup is derived compositionally from inherited inputs, explicit
  startup-file options, and scanner-preserved invocation modes. Bash interactive
  non-login mode schedules startup unless `--norc` is present, while Bash login
  mode schedules startup unless `--noprofile` is present. These suppressors
  remove only the corresponding mode-derived route; they do not prove an
  unavailable inherited environment absent, and explicit `--rcfile` or
  `--init-file` remains startup-bearing with protected paths directly denied;
- every successfully parsed ordinary zsh invocation schedules startup because
  zsh reads its installation-global zshenv before `RCS`, `GLOBAL_RCS`, or `-f`
  can suppress later files. The scanner retains the reviewed zsh named-option
  identities, but none is treated as proof that all startup execution is absent.
  Fish startup remains potential unless its reviewed `--no-config`/`-N` mode is
  present, although fish command source remains hard-blocked pending a dedicated
  parser. Unreviewed sh, dash, and ksh interactive/login startup modes remain
  opaque; unsupported named modes also become opaque rather than passing; and
- every recognized `find -exec` or `-execdir` action contributes either a direct
  invocation child or an opaque repeated-execution child, so a known sibling
  cannot erase unresolved execution;
- reserved-word `time -p` is represented by the pinned Tree-sitter patch's
  contextual external token and projected without deleting command words;
- builtin transitions now return complete `BashShellState`, and `unset` models
  reviewed `-f`, `-v`, `-n`, clustered-option, `--`, dynamic-name, branch,
  group, and subshell behavior across both environment and function domains;
- the shared option scanner preserves recognized required options whose present
  value is unresolved. Dynamic Bash/zsh command source becomes an opaque source
  child, while dynamic fish command or init source remains a mandatory guard
  denial;
- the GNU `find` handler advances by reviewed primary arity, validates exact
  action terminators, keeps dynamic expression/action positions opaque, and
  continues to inspect concrete sibling actions; and
- Pi maps every proven core guard denial to a pre-execution block, including
  future guard names that do not need specialized notification text;
- unresolved words retain non-serializable symbolic fragment/cardinality shape,
  and fish source/init denial runs in generic structural preflight before
  retained command substitutions; and
- internal work-item exhaustion now drains admitted work before choosing between
  concrete denial and the stored admission failure.

Focused verification passed 378 tests with 9,665 assertions. Full verification
passed 595 Bun tests with 26,520 assertions, all 11 x86_64-linux Nix flake
checks, and `git diff --check`. A fresh independent adversarial review has not
yet been run for these follow-up corrections.
