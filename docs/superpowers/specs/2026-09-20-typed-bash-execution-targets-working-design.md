# Typed Bash execution targets and process effects

Status: implemented working design, pending final independent review

Date: 2026-09-20

Related design: `2026-09-11-stateful-bash-cst-authorization-walker-design.md`

Current implementation checkpoint: `b0e5552 fix: retain executor compound bodies`

This is a temporary coordination artifact intended to survive context
compaction and session handoff. It records the agreed direction and unresolved
decisions for the Bash walker redesign. Once the redesign is implemented and
approved, its durable decisions should be merged into the primary walker
design and this file should be removed.

## Purpose

The Bash authorization walker must discover every statically knowable child
execution while preserving the distinction between:

- a normalized executable invocation;
- an already-parsed Bash statement body;
- source text interpreted as another shell program;
- an opaque execution route that cannot be derived safely; and
- the semantic process boundary introduced by an execution route.

The implementation at the original checkpoint represented every recursively analyzed child as
shell source. Ordinary argv wrappers quote their child argv, join it into a
string, parse it as Bash, and schedule the resulting statements. Recent work
also added regex-based source rewriting and reparsing to recover `time` and
`coproc` compound bodies that the pinned Tree-sitter grammar does not model.

That representation is no longer acceptable. It fabricates shell semantics for
argv, loses structured syntax and scope, consumes nested-script budgets for
ordinary process wrappers, and cannot represent process topology.

## Historical checkpoint

The branch from `70abf52` through `b0e5552` contains substantial GitHub CLI
policy hardening and passes its current tests. The latest complete verification
at `b0e5552` was:

- 495 Bun tests passed;
- 23,456 assertions passed;
- all 11 x86_64-linux Nix flake checks passed; and
- `git diff --check` passed.

Those results prove the current test contract, not architectural correctness.
The checkpoint is not approved because an independent review reproduced
multiple High findings in the parser, walker, wrapper handlers, and Pi adapter.

Do not extend the regex compound recovery or add more source-reconstruction
special cases while this redesign is pending.

## Current implementation status

The typed invocation, statements, source, and opaque targets are implemented.
Ordinary argv wrappers dispatch normalized invocations directly; `time` and
`coproc` are projected from a pinned Tree-sitter patch; current-scope child
completion propagates complete `BashShellState`; recognized unresolved execution
becomes an explicit redacted opaque target; and Pi blocks incomplete analysis
when approval is unavailable.

The September 20 follow-up also models `time -p` in the grammar, preserves
recognized shell options with dynamic required values, applies `unset` to both
environment and function state, and parses GNU `find` actions by expression
position and primary arity. Fish command source remains blocked pending a
dedicated parser, including when the command or init source is dynamic. Final
verification passed 595 Bun tests with 26,520 assertions, all 11 x86_64-linux
Nix flake checks, and `git diff --check`. The independent adversarial review
gate remains pending.

## Agreed model

### Two independent dimensions

Child representation and process creation are independent dimensions.

An execution target describes what is executed and how it is represented to
the analyzer. A process effect describes the reviewed semantic process boundary
introduced by that execution route.

Neither dimension implies the other:

- Bash `time` has a structured body but adds no process boundary of its own.
- External GNU `time` receives argv and launches and waits for a child.
- `env` receives argv and normally replaces itself with its child.
- `bash -c` receives source text that must be parsed in the selected dialect.
- `coproc` has a structured Bash body and creates an asynchronous subshell.

### Execution targets

The target model should minimally distinguish:

```ts
type ExecutionTarget =
  | {
      kind: "invocation";
      invocation: NormalizedCommand;
    }
  | {
      kind: "statements";
      statements: readonly BashStatement[];
      scope: "current" | "subshell";
    }
  | {
      kind: "source";
      source: string;
      dialect: "bash" | "sh" | "fish" | "zsh";
      scope: "current" | "subshell";
    }
  | {
      kind: "opaque";
      reason: ExecutionUnknownReason;
    };
```

An invocation target is already normalized executable, argv, redirect, and
environment data. It must be dispatched directly and must never be quoted back
into shell source.

A statements target contains syntax already produced by the parser adapter. It
must be scheduled directly with its declared scope and must never be serialized
and reparsed.

A source target exists only when source interpretation is an actual behavior of
the route, such as `eval`, `sh -c`, or default-shell `watch`. It must name its
dialect. Unsupported dialects require an explicit policy: fish source is
blocked, while zsh currently uses Bash parsing as a documented best-effort
compatibility alias pending a matching parser.

An opaque target records that execution may occur but cannot be derived safely.
It prevents automatic authorization and carries only redacted provenance.

### Process effects

The initial effect vocabulary is:

```ts
type ProcessEffect =
  | "none"
  | "exec-replace"
  | "spawn-and-wait"
  | "spawn-async"
  | "spawn-repeated"
  | "unknown";
```

The effect is a semantic process summary, not a promise that a specific kernel
syscall occurs. Implementations may use `fork`, `vfork`, `clone`,
`posix_spawn`, or direct `execve` depending on executable version, shell
optimization, platform, and control-flow context.

Exact syscall claims require a separately pinned implementation contract. The
common model records only the portable process effect needed for authorization
and steering.

The effect should describe the additional behavior introduced by the analyzed
route. The shell's launch of an external executable is already represented by
the invocation node; a handler summary describes what that executable does to
reach its child.

### Child execution

Handlers return child executions rather than source continuations:

```ts
interface ChildExecution {
  readonly target: ExecutionTarget;
  readonly process: ProcessEffect;
  readonly environment: Environment;
  readonly provenance: BashExecutionProvenance;
}

interface StructuralResult {
  readonly outcome: Outcome;
  readonly children: readonly ChildExecution[];
  readonly statePatch?: EnvironmentPatch;
}
```

The final shape may vary as implementation reveals ownership boundaries, but
the target and process dimensions must remain explicit and independent.

Implemented refinement: caller-visible shell state is represented separately
as `BashShellState`, containing environment bindings, function candidates, and
missing-function facts. Child descriptors still carry their effective
environment because handlers own executable environment transformation, while
the walker combines that environment with the complete parent state before
scheduling. Current-scope completion propagates the complete resulting state;
subshell completion discards it; and branch/fanout joins use one centralized
complete-state operation.

Opaque targets now carry a closed, redacted `ExecutionUnknownReason` rather
than an unqualified opaque marker. When a registered child-launching structural
handler returns an indeterminate or failed parse without a child plan, dispatch
normalizes it to an opaque child. The walker turns that child into the existing
profile-independent analysis-failure outcome, so every adapter reaches its
incomplete-analysis prompt/block boundary even when no permission profile is
enabled. Reasons contain classifications only, never source, argv,
environment values, protected paths, or secret-bearing values.

Parser failures retain an immutable projected program containing only complete,
error-free root statements with a concrete statement boundary before malformed
syntax. The walker analyzes that prefix and appends redacted failure afterward.
The same contract applies to top-level input and source targets created by
`eval`, shell `-c`, and default-shell `watch`; malformed nested syntax is never
rewritten, reparsed as a prefix, or fabricated into statements. A denial found
in the complete prefix remains stronger than the trailing failure.

Opaque current-scope execution, used for direct `source` and `.`, taints caller
environment facts and marks existing function candidates as possibly replaced
while preserving them as conservative alternatives. Shell startup routes are
separate isolated opaque children: explicit startup-file options and inherited
startup environment inputs are represented even when the main `-c` source is
also available. Protected startup paths still deny before child scheduling.

The current implementation deliberately retains the existing child collection
and conservative join semantics. Explicit `single`/`alternatives`/`repeated`
execution-plan composition is deferred until a migrated handler needs the
distinction for caller-visible state or authorization. This avoids a flag-day
handler rewrite while enforcing the immediate totality invariant.

## Execution classification

The following table is the starting classification. Option-dependent behavior
must remain option-dependent rather than being collapsed into one executable
default.

| Form | Child target | Additional process effect |
| --- | --- | --- |
| Bash reserved-word `time` | structured statements or pipeline | `none` |
| external GNU `time` | invocation | `spawn-and-wait` |
| Bash `coproc` | structured statements, subshell scope | `spawn-async` |
| `command` | invocation | `none` |
| `exec` | invocation | `exec-replace` |
| `env` | invocation with transformed environment | `exec-replace` |
| `nice` | invocation | `exec-replace` |
| `stdbuf` | invocation | `exec-replace` |
| `strace` child mode | invocation | `spawn-and-wait` |
| `timeout` | invocation | `spawn-and-wait` |
| `setsid` | invocation | option-dependent `exec-replace`, spawn, or unknown |
| foreground `sudo` | invocation | reviewed version/mode dependent |
| background `sudo -b` | invocation | `spawn-async` or unknown |
| `watch --exec` | invocation | `spawn-repeated` |
| default-shell `watch` | source | `spawn-repeated` |
| `xargs` | invocation template with runtime-derived operands | `spawn-repeated` |
| `find -exec` | invocation template with substitutions | `spawn-repeated` |
| Bash-compatible shell `-c` | source | determined by the shell invocation envelope |
| `eval` | source, current scope | `none` |
| `source` or `.` without trusted contents | opaque file-content target | `none` |
| unknown executable or wrapper grammar | opaque | `unknown` |

Each recognized `find -exec` and `-execdir` action independently contributes
one child. A statically closed action contributes an invocation child; an
unresolved or unterminated action contributes an opaque repeated-execution
child. Mixed action lists retain both, regardless of action ordering.

This table is not authorization policy. Process effects may become policy input,
but the operator must decide separately which effects force confirmation.

## Bash `time`

Bash `time` is a reserved-word modifier over an already parsed pipeline or
compound statement. It does not inherently create a process.

Observed behavior on the supported development system:

- `time true` creates no child process when `true` is the Bash builtin.
- `time external-command` creates only the process needed for the external
  command.
- `time { X=inner; }` executes the brace body in the current shell and retains
  `X=inner`.
- `time ( X=inner )` preserves the subshell isolation already expressed by the
  body.

The syntax adapter must retain the timed body because it may be a pipeline or a
compound statement. The walker must preserve the body's existing scope. Bash
`time` must not share a handler grammar with `/usr/bin/time` or `command time`.

External GNU `time` is an ordinary executable invocation. Its reviewed handler
parses GNU argv and emits an invocation child with `spawn-and-wait` semantics.
An argument such as `NAME=value` is an executable name unless another wrapper
explicitly assigns environment semantics; it must not be reconstructed as a
Bash prefix assignment.

## Bash `coproc`

`coproc` is Bash syntax with an asynchronous child and connected pipes. Its
body may be a simple command or a compound Bash statement.

The parser adapter must decide whether an optional coprocess name exists from
Bash grammar, not identifier capitalization. In particular:

- `coproc worker command` is a simple command whose executable is `worker`;
- `coproc worker { command; }` is a named compound coprocess; and
- `coproc worker ( command )` is a named compound coprocess.

The walker schedules the body exactly once in subshell scope and records a
`spawn-async` effect. The body must not also remain as an independent top-level
statement.

## Layer responsibilities

### Syntax adapter

The syntax adapter projects Bash syntax into the backend-neutral CST model. It
owns syntax classification and source spans, but not executable option grammar
or authorization policy.

It must represent reserved-word `time` and `coproc` explicitly enough to retain
their bodies and syntax-level attributes. It must not smuggle bodies through an
`unsupported-word`, infer coprocess names from capitalization, or recognize an
ever-growing Bash grammar with regular expressions.

The former source-blanking and reparsing recovery in `src/shell.ts` was a failed
approach and has been deleted in favor of explicit syntax projection.

### Walker

The walker owns Bash environment state, assignments, scope, functions, control
flow, branch joins, pipelines, and statement sequencing.

It converts structured syntax into dispatchable invocations or structured
children without losing scope. It must not parse executable-specific options or
reconstruct child argv as source.

### Structural handlers

Handlers own one executable's reviewed option grammar, envelope effects,
environment transformation, and child execution summaries.

Handlers may produce invocation, source, or opaque targets. They do not parse
Bash syntax. Bash reserved words do not resolve through basename-based external
handler registration.

GNU unique long-option abbreviations are executable grammar. Each supporting
handler must opt into one shared canonicalization primitive backed by its exact
option table. Ambiguous and unsupported prefixes remain opaque.

Implemented refinement: `src/bash/options.ts` provides the shared declarative
scanner for no-value and required-value options, separate/attached/equals
values, short clusters, `--`, immediate and deferred terminal options, operand
stopping, and explicit exact or unique-prefix long-option resolution. Deferred
terminals model Bash/zsh `c`: source follows the rest of the cluster and every
option value consumed by that remainder. Fish retains immediate attached or
separate `c` values. Shell interpreters and `exec` are the first consumers.
Existing wrapper-specific parsers may migrate
incrementally, but their recognized parser failures are already normalized to
opaque execution.

Resolved words now have an analysis-internal symbolic companion for partial
shape: literal/unknown fragments and `one`, `one-or-more`, or `zero-or-more`
field cardinality. The companion is held in a `WeakMap`; the public unknown word
still contains only its redacted reason. Shape-aware option scanning may prove a
value-taking option identity from a static attached/equal prefix, but that proof
may only produce denial or opacity. It cannot produce an allow.

Structural handlers may provide a deny-only preflight. For commands with
retained substitutions, the walker performs abstract normalization, then
preflight, then the retained substitutions, then ordinary normalization and
dispatch. Commands without retained work proceed directly to ordinary dispatch.
A preflight result is exactly `continue` or concrete `deny`; it has no
child-scheduling capability. Definite shell-function resolution bypasses
external-handler preflight. Fish uses this contract for command and init source
options, while ordinary fish invocations remain outside the hard-denial
boundary. Typed invocation children still pass through normal fish dispatch and
receive the equivalent denial.

### Policy observers

Policy observers consume normalized invocation and structural metadata. They
cannot schedule children or alter execution structure. Denial evidence remains
globally dominant across all scheduled targets.

### Runner

The runner should become the sole scheduler of execution targets, continuations,
branches, joins, and budgets.

The current walker owns a private synchronous `Work[]` agenda inside an outer
runner target. This duplicates scheduling and budget concepts and prevents the
runner from observing the real execution graph. The redesign should converge on
one scheduler rather than preserving both abstractions.

Until that consolidation, internal `maxWorkItems` is explicitly a total
admission budget. Failed admission stores redacted failure and rejects only the
new work; already-admitted internal agenda entries drain, and any concrete deny
they produce dominates. `maxSteps` remains an immediate execution-stop budget.
The outer runner already drains queued work after queue-admission failure and
therefore required no semantic change.

### Harness adapters

Adapters map complete, incomplete, deferred, and denied analysis into harness
behavior. An adapter without an equivalent native prompt must explicitly
confirm or block incomplete analysis.

Core budget exhaustion remains an incomplete neutral analysis according to the
original design. It must not become `ignore` in Pi merely because no policy
evidence was reached before exhaustion.

## In scope

- Typed invocation, statements, source, and opaque execution targets.
- Semantic process effects and graph observability.
- Direct dispatch of normalized argv children.
- Explicit Bash `time` and `coproc` syntax projection.
- Removal of regex/source-blanking compound recovery.
- Removal of argv-to-source reconstruction for ordinary wrappers.
- One scheduler and one coherent budget model.
- Dialect-aware source targets.
- GNU unique-prefix handling for reviewed GNU wrapper grammars.
- Correct incomplete-analysis behavior in Pi and equivalent adapters.
- Execution-graph, scope, multiplicity, process-effect, and equivalence tests.
- Preservation of current GitHub CLI profile ownership and denial dominance.

## Out of scope

- Claiming exact kernel syscalls without a pinned executable implementation.
- A complete Bash interpreter or full symbolic execution.
- Executing source, expansions, commands, or script files during analysis.
- Reading script-file contents from the host without an explicit trusted input
  contract.
- Automatically supporting arbitrary fish or zsh syntax with the Bash parser.
- Turning every process effect into an authorization policy before operator
  decisions are made.
- Deliberate encoded evasion outside the repository threat model.
- Rewriting unrelated GitHub CLI policy semantics during the walker migration.

## Resolved findings that drove the migration

### High: wrong scope and duplicate bodies

Former references:

- `src/shell.ts` compound recovery and synthetic unsupported word;
- `src/bash/walker.ts` retained statements always using subshell scope; and
- `src/bash/handlers/command-executors.ts` `time` and `coproc` reconstruction.

Former effects included timed brace writes being lost, protected reads becoming
invisible after a timed assignment, and named coprocess subshell bodies being
scheduled twice.

Architectural owner: syntax adapter plus walker scope scheduling.

### High: incomplete and non-recursive recovery

The former regex omitted valid forms such as negated timed pipelines,
escaped-newline separation, and `select`. Recovered nested executors are
projected without the complete recovery map.

Architectural owner: syntax adapter. Do not patch this in command handlers.

### High: argv wrappers are reparsed as source

`BashDispatchContinuation` stored only source text. `continueFrom()` quoted argv
and schedules a nested parse. This consumes nested-script budget, fabricates
assignment syntax, loses process effects, and collapses source provenance.

Architectural owner: execution-target contract, dispatcher, and runner.

### High: wrapper option abbreviations hide children

GNU unique prefixes were unsupported in older `timeout`, `env`, `nice`,
`setsid`, and `stdbuf` handlers. The child is not traversed when a valid prefix
is rejected.

Architectural owner: reviewed executable grammars and shared exact/unique
option resolution.

### High: Pi fails open on incomplete analysis

Budget exhaustion could occur before policy evidence was observed. The configured
permission became `ignore`, and Pi confirmed only `defer`.

Architectural owner: analysis disposition and harness adapter mapping.

### Medium: non-Bash source is parsed as Bash

Fish and zsh `-c` options were recognized, but every source continuation reached
the Bash parser. Fish is now denied and zsh is an explicit best-effort Bash
compatibility alias pending a matching parser.

Architectural owner: source target dialect and parser availability.

### Medium: parser work is outside analysis budgets

Tree parsing, syntax-error traversal, projection, recovery parsing, and deep
freezing occur before the runner budget applies. Several paths remain recursive.

Architectural owner: parser adapter limits and eventual scheduler accounting.

## Implemented migration sequence

The migration must remain incremental. Every phase should preserve a runnable,
tested repository and should avoid a flag day across all handlers.

### Phase 0: freeze and characterize

- Treat `b0e5552` as a tested but unapproved checkpoint.
- Add ordinary regression tests for wrong timed scope, duplicate coproc
  traversal, argv-wrapper depth exhaustion, Pi incomplete analysis, and every
  confirmed wrapper abbreviation.
- Keep those tests failing until the implementation satisfies their asserted
  behavior; do not mark known defects as expected failures or skipped tests.
- Preserve the tests added for GHES GraphQL and denial dominance.
- Do not extend compound recovery.

### Phase 1: introduce target and effect types in shadow mode

- Add `ExecutionTarget`, `ProcessEffect`, `ChildExecution`, and graph records.
- Keep existing authorization outcomes unchanged.
- Record expected target/effect classifications alongside current continuations.
- Add graph-level tests before migrating behavior.

Exit criterion: every currently modeled recursive route has an explicit shadow
classification, and graph recording emits no source or secret values.

### Phase 2: direct invocation scheduling

- Add runner support for invocation targets.
- Migrate `command`, `exec`, `env`, `nice`, and `stdbuf` first.
- Migrate `timeout`, `strace`, `setsid`, and `sudo` after option-dependent
  effects are specified.
- Stop incrementing nested-script depth for invocation targets.
- Keep policy observers and denial merging unchanged.

Exit criterion: migrated wrappers no longer call `continueFrom()` and preserve
the same or stronger policy outcomes under focused and property tests.

### Phase 3: templates and repeated execution

- Migrate `watch --exec` to invocation targets.
- Keep default-shell `watch` as a source target.
- Model `xargs` and `find -exec` as invocation templates with runtime-derived
  argument taint and repeated process effects.
- Decide whether one approval may cover repeated prompt-gated execution.

Exit criterion: target kind, process effect, multiplicity, and unknown runtime
  inputs are visible in tests and audit data without retaining values.

### Phase 4: explicit Bash executor syntax

- Decide whether to patch/fork the pinned Tree-sitter Bash grammar or implement
  a narrowly bounded adapter replacement.
- Add explicit backend-neutral syntax for timed bodies and coprocess bodies.
- Schedule Bash `time` bodies in their original scope with process effect
  `none`.
- Schedule coprocess bodies once in subshell scope with `spawn-async`.
- Remove `time` and `coproc` from generic basename-based wrapper registration.
- Delete source blanking, regex compound recovery, synthetic unsupported words,
  and capitalization-based name inference.

Exit criterion: all valid reviewed compound forms project structurally, nested
forms work without reparsing, and malformed neighboring syntax remains an
explicit parse failure.

### Phase 5: source targets and dialects

- Convert `eval`, Bash-compatible shell `-c`, and default-shell `watch` to
  explicit source targets.
- Preserve current-scope versus subshell-scope semantics.
- Use a matching parser backend where supported.
- Block fish source until a matching parser is available.
- Parse zsh source with the documented best-effort Bash compatibility alias
  until a matching parser is available.

Exit criterion: only genuine source interpreters invoke `parseBashProgram()` or
another dialect parser.

### Phase 6: consolidate scheduling and budgets

- Move target scheduling, branches, joins, and continuation budgets into the
  runner.
- Remove the walker's private agenda or remove the unused outer runner; do not
  retain both.
- Distinguish statement depth, source parse depth, process graph size, and total
  analysis work where separate limits are justified.
- Bound parser input, node count, projection work, and reparses.

Exit criterion: one scheduler owns all reachable work and every finite limit has
an explicit incomplete-analysis result.

### Phase 7: adapter completion semantics

- Make incomplete analysis explicit before profile ownership reduces evidence.
- Preserve neutral/native-prompt behavior where the harness provides it.
- Require Pi to confirm or block incomplete analysis.
- Decide and test Pi behavior when no UI is available.

Exit criterion: no harness proceeds silently after parser or budget failure.

### Phase 8: cleanup and supersession

- Remove `BashDispatchContinuation` source-only APIs.
- Remove `continueFrom()` from invocation wrappers.
- Remove obsolete executor handlers and compatibility names.
- Merge approved architecture into the primary walker design.
- Delete this working document after its open decisions and findings are closed.

## Testing strategy

Final-verdict tests remain necessary but are insufficient.

### Graph tests

Assert:

- target kind;
- process effect;
- child count and multiplicity;
- current-shell versus subshell scope;
- normalized executable and argv boundaries;
- transformed environment facts;
- redacted provenance and source spans; and
- absence of retained secret-bearing values.

### Equivalence tests

Use isolated real Bash fixtures for the supported subset to compare:

- timed brace-group writes;
- timed subshell isolation;
- coprocess isolation and single body scheduling;
- wrapper argv and environment propagation;
- external GNU `time` versus Bash reserved `time`;
- direct `exec` replacement semantics where observable;
- repeated wrapper templates where a deterministic fixture is possible; and
- nested invocation wrappers without source-depth consumption.

### Property tests

Generate:

- reviewed option orderings and unique GNU prefixes;
- nested wrapper stacks around a fixed denied child;
- nested structured executors;
- unknown operands at every child boundary;
- process-effect variants controlled by options;
- budget values immediately below, at, and above exhaustion; and
- Unicode and escaped-newline syntax around source spans.

### Adapter and package tests

Prove equivalent denial, deferral, and incomplete-analysis behavior through:

- Claude Code hooks;
- OpenCode hooks;
- Pi hooks, including UI rejection, prompt errors, and no-UI behavior; and
- Nix-built packaged artifacts.

### Required gates

Every implementation checkpoint requires:

- focused unit and property tests;
- full `bun test`;
- `nix flake check 'path:.'`;
- `git diff --check`; and
- a new independent Critical/High adversarial review.

All adversarial findings must be presented to the operator before corrections
are made.

## Operator decisions

The redesign uses the following decisions. Repeated approval remains open for
a separate policy change.

### Parser strategy

Resolved: use a pinned patch of `tree-sitter-bash` 0.25.1 that emits explicit
`time_statement` and `coproc_statement` nodes. The patch, regeneration metadata,
and generated WASM artifact are versioned in this repository. Source-rewrite
recovery is removed.

### Process effects as policy input

Resolved: process effects are explicit, tested observational metadata. Making
individual effects authorization policy requires a separate reviewed decision.

### Pi incomplete analysis

Resolved: Pi prompts when UI exists and blocks on rejection, prompt error, or
missing UI.

### Non-Bash dialects

Resolved: fish command strings are blocked until a dedicated parser and
equivalence contract are approved. zsh command strings use Bash parsing as an
explicit best-effort compatibility alias, with a TODO to replace it with a
matching parser.

### Source-file trust

Resolved: script files remain opaque in this redesign.

### Repeated approval

Choose whether one authorization decision can cover repeated execution by
`watch`, `xargs`, or `find` when the child is prompt-gated rather than denied.

Recommendation: preserve denial immediately and defer approval semantics until
the process graph can represent multiplicity.

## Resumption checklist

At the start of a future session:

1. Read this document and the primary walker design.
2. Inspect `git status` and do not modify unrelated worktree changes.
3. Confirm the current commit and preserve unrelated worktree changes.
4. Run focused tests, full Bun tests, Nix checks, and `git diff --check`.
5. Run a fresh independent Critical/High adversarial review.
6. Present every review finding to the operator before making corrections.

## Completion criteria

This redesign is complete only when:

- ordinary argv wrappers dispatch invocation targets without source reparsing;
- only genuine source interpreters recursively parse source;
- Bash `time` preserves body scope and adds no process boundary of its own;
- Bash `coproc` schedules one structured body in asynchronous subshell scope;
- external GNU `time` is distinct from Bash reserved `time`;
- process effects are visible and tested without overclaiming exact syscalls;
- one scheduler owns target traversal and finite analysis budgets;
- incomplete analysis cannot silently execute in any harness;
- all existing policy ownership and denial-dominance invariants remain intact;
- unit, property, equivalence, adapter, and package tests pass;
- no unresolved Critical or High adversarial findings remain; and
- approved durable decisions have been merged into the primary design.
