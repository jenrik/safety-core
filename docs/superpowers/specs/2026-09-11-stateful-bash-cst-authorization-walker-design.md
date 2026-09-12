# Stateful Bash CST authorization walker design

## Context

The current authorization policies call `parseBash()` to flatten a Bash input
into `SimpleCommand[]`. That loses the state and nesting needed to correctly
interpret shell assignments, functions, and programs that execute another
program. Consequently, wrapper handling is bespoke and policy-specific.

This design replaces flattened-command authorization with a stateful walk of a
Bash CST. It evaluates a deliberately bounded, statically resolvable subset of
Bash and dispatches every resolved program to a named command handler. The
design must support transparent executors such as `strace`, `env`, `nice`,
`timeout`, `xargs`, and `sh -c` without assuming any two commands are
semantically equivalent.

The walker is an authorization analysis, not a Bash executor. A future minimal
TypeScript Bash implementation may use the same program and word interfaces as
another CST/runtime backend.

## Goals

- Resolve statically knowable shell bindings and word expansions precisely
  enough to analyze the commands actually invoked.
- Model Bash binding lifetime precisely for the supported subset.
- Inspect recursively executed commands through command-specific handlers.
- Permit an automatic allow only when every reachable execution is proven
  safe; preserve the harness's native prompt for uncertainty.
- Short-circuit immediately on an explicitly forbidden command.
- Keep walker and handler functions pure, deterministic, stack-safe, and
  independently testable.
- Provide unit, property, and isolated real-Bash equivalence coverage.

## Non-goals

- Full symbolic execution or a complete Bash interpreter.
- Reading the host environment implicitly from the core walker.
- Executing shell expansions, command substitutions, sourced files, or target
  commands during authorization.
- Dynamically configuring command grammars or handler behavior. Those remain
  reviewed TypeScript code.

## Core architecture

### Syntax adapter and iterative runner

The walker consumes a small Bash program/CST adapter interface rather than
depending directly on `web-tree-sitter` node types. Initially the adapter wraps
the existing `tree-sitter-bash` parser. A future TypeScript Bash runtime can
provide the same interface.

The runner is iterative. A walker or handler returns an immutable next step
rather than recursively calling its successor:

```ts
type Step =
  | { kind: "continue"; state: WalkState; target: DispatchTarget }
  | { kind: "fork"; state: WalkState; targets: readonly DispatchTarget[] }
  | { kind: "result"; state: WalkState; outcome: Outcome };
```

`continue` is the stack-safe equivalent of a tail call. `fork` is used only
when a construct has multiple reachable continuations. The runner maintains an
explicit work agenda, so neither normal handler chaining nor branching consumes
the JavaScript call stack. Every function is pure: it receives immutable input
and returns a logically cloned state. Implementations may structurally share
unchanged persistent data, but may never mutate state, argument cursors, or
option records received from a caller.

### Command normalization and dispatch

For each Bash `command` CST node the walker:

1. creates a command-local environment overlay;
2. consumes assignment prefixes in source order, expanding each against the
   state accumulated so far;
3. expands the executable, arguments, and redirects against the caller
   environment before prefix assignments take effect;
4. sends the normalized invocation to `dispatchCommand`; and
5. discards the overlay after an external command, unless Bash lifetime rules
   make the assignment persistent.

For example, the temporary assignment overlay in:

```bash
F="BAR" D="GAR" echo "$D" "$F"
```

causes the `echo` handler to receive `argv: ["", ""]` when `F` and `D` are
unset in the caller environment, and an effective child environment containing
`F=BAR` and `D=GAR`; it does not modify the parent shell frame. Prefix
assignments expand left-to-right for their own values and construct the child
environment, but they are not visible to expansion of words in that same
command. In the supported default shell mode, direct expansion of an unset
binding yields a known empty string; an `Unknown` binding remains unknown.

The generic dispatcher resolves exactly one named command handler. The fallback
is itself an `unknown-command` handler; no implicit generic-command equivalence
exists. A normalized invocation contains resolved words with source provenance,
the effective child environment, and a cursor over remaining operands.

Handlers own their executable's option grammar. A handler may consume only its
documented flags in any positions it supports, storing typed option state in a
new cursor, then pass that cursor to a subhandler. This supports paths such as
`gh` -> `pr` -> `create` without globally reordering arguments or interpreting
another command's flags.

A handler may directly evaluate its invocation, recurse into the dispatcher
for an explicit child program, or emit indeterminate execution evidence. For
example, `strace` parses its options before dispatching a statically resolvable
child; `sh -c "$COMMAND"` recurses only if `COMMAND` is known; and `xargs` or
`find -exec` emits an indeterminate child execution when its actual child cannot
be derived conservatively.

## Abstract Bash state

`WalkState` is an immutable snapshot of shell frames, binding attributes,
control-flow context, and finite evaluation budgets. A binding has a value
state of `Known(value)`, `Unknown(reason)`, or `Unset`, plus its export and
readonly attributes.

### Persistent frame storage and branch checkpoints

Use parent-linked persistent frames, not a stack of cloned maps. A frame is
created only for a real Bash scope boundary (for example a function, subshell,
or command-local prefix-assignment overlay). A normal assignment produces a
copy-on-write delta for the affected frame's binding store; unchanged bindings
and ancestor frames are shared. Consequently, state-version depth does not
become scope-stack depth and linear execution does not retain a full map per
step.

The iterative runner uses continuation liveness to choose representation:

- On a linear `continue`, the prior snapshot has no future consumer other than
  any explicit return continuation. The next snapshot shares persistent
  structure and the previous version becomes collectible.
- On `fork`, the runner freezes one immutable checkpoint. Each branch starts
  from it and records only its per-frame binding deltas and write sets.
- At a branch join, compare only bindings written since the checkpoint. Retain
  a value only when reachable branches agree; otherwise retain the name with an
  `Unknown` value.

An unsupported construct capable of arbitrary mutation uses a compact
frame-level/default-lookup taint rather than eagerly replacing every binding.
Prefix assignments use a short-lived overlay that is discarded after the
invocation.

Handlers remain pure and return logical snapshots or patches; they never mutate
an input frame. The runner may internally use a transient builder only when it
has proven exclusive ownership of a linear path, and must freeze that builder
before a fork, a saved continuation, or any diagnostic/test snapshot. Compact a
frame's delta chain when it exceeds an internal representation threshold, at a
branch join, or before a stable snapshot escapes. These optimizations are
observationally identical to immutable state updates.

### Initialization and trust boundary

The adapter passes either a verified snapshot equivalent to the Bash invocation
environment or an explicitly unavailable environment. Only the former seeds
the root frame with all inherited variables. When a harness cannot establish
that equivalence, the root frame has no inherited bindings and references such
as `$VARIABLE` resolve to `Unknown`. The core walker never consults
`process.env`; adapters own this harness-specific decision.

Resolved or inherited values, especially secret-bearing ones, never appear in
diagnostics, audit records, test snapshots, or persistent traces. Diagnostics
may report a variable name, source range, and redacted resolution category.

### Lifetime and scope

- A standalone assignment updates the current shell frame.
- Prefix assignments are visible only through the current invocation's
  temporary overlay and derived child environment, including a function or
  builtin invocation. The overlay is restored after that invocation; only an
  assignment-only statement or an explicitly modeled Bash special-builtin rule
  can persist a prefix assignment in the caller frame.
- Function invocation creates a fresh call frame seeded from the caller state.
  Lookup follows Bash's dynamic scope: a function sees caller bindings; `local`
  creates a frame-local shadow; and a non-local assignment updates the nearest
  caller-visible binding. A function-call prefix overlay lasts only for that
  invocation, while ordinary non-local writes made by its body propagate to its
  caller as Bash specifies.
- A subshell or pipeline child receives copied state and never mutates its
  parent. A brace group uses the current frame and retains mutations.
- Modeled builtins implement `export`, `readonly`, and `unset` by updating the
  relevant binding attributes or presence.

Sequential execution passes state forward. Conditional and branching execution
merges every reachable continuation: a binding remains known only when all
reachable states agree; otherwise its known name is retained with an `Unknown`
value.

Unsupported state-changing syntax never stops traversal. If affected bindings
are syntactically known, only those bindings become unknown. If a construct can
mutate arbitrary bindings, the walker taints existing and subsequently resolved
bindings conservatively. A modeled, deterministic later assignment may replace
an unknown binding with a known one; uncertainty must never become knowledge
merely through propagation or branch merging.

## Termination and outcomes

The state carries finite limits for function recursion depth, nested-script
depth, total continuation steps, and branch/work-item count. Function recursion
consumes budget even though execution is iterative. Reaching any limit produces
an `analysis-failure` outcome with redacted provenance, ensuring nontermination
is impossible.

Use a generous candidate default profile of function depth 128, nested-script
depth 64, total steps 100,000, and work items 10,000. Final numeric defaults
are contingent on implementation measurement: an input that exhausts every
default limit should complete analysis in roughly 1,000 ms or less. This is a
calibration guideline for choosing structural limits, not a runtime clock limit
or an additional authorization outcome.

Each handler produces one of:

- `safe`: the execution it represents is proven safe;
- `indeterminate`: an executable, child command, word, or state cannot be
  resolved sufficiently;
- `failure`: a finite analysis limit, malformed relevant syntax, or other
  analysis failure occurred; or
- `deny`: a policy has proven an explicitly forbidden execution.

The runner combines outcomes monotonically:

- `deny` terminates immediately and returns deny;
- `indeterminate` and `failure` are sticky evidence that prevents an allow but
  do not stop traversal, because later execution may prove a deny;
- the final result is allow only when every reachable execution is safe;
- otherwise the final result is neutral, leaving the harness's native permission
  behavior intact.

The existing `ghPrCreate` parser-deployment failure remains a policy-specific
fail-closed denial. Ordinary unresolved analysis and ordinary budget exhaustion
remain neutral.

## Policies, adapters, and configuration

The core exposes one walker-backed authorization entry point conceptually like:

```ts
analyzeBashAuthorization({
  source,
  initialEnvironment,
  limits,
  enabledPolicies,
})
```

Hard-block adapters evaluate all relevant invocations and block on deny.
Permission hooks set the native status to allow only on a complete safe result;
neutral, indeterminate, and bounded-analysis failure leave the native prompt
unchanged.

Add a `bashAnalysis` object to the shared runtime `profiles.json`. Its values
are rendered only through Nix Home Manager options and include validated limits
for recursion, nested scripts, total steps, and work items. Existing profile
options continue to choose participating reviewed policies. Handler grammars
and policy rules are not runtime configuration. The Nix default values are
selected from the generous candidate profile only after the required
cap-exhaustion performance measurement.

Migrate current flattened-command policy entry points progressively to handler
or handler-attached policy registrations. Retain `parseBash()` temporarily for
compatibility; remove each old flattened path only after its walker-backed
replacement has matching regression and equivalence coverage.

## Verification

### Unit and property tests

Test pure components independently:

- ordered assignment expansion, prefix-overlay lifetime, export/unset/local
  behavior, function call frames, dynamic lookup, subshell isolation, and
  branch merges;
- command normalization, handler option parsing, subhandler routing, and
  nested-command discovery;
- immutable input/output behavior and iterative continuation execution;
- deny dominance, finite termination under every budget, flag-order
  permutations, and isolation between distinct function invocations;
- the uncertainty invariant: a binding not written by a step cannot emerge
  known after being weakened to unknown, and known values are introduced only
  by modeled deterministic writes independent of unknown inputs.
- cap-exhaustion performance calibration: measure the finalized defaults on
  deeply nested, recursive, and branching supported inputs, and record that
  analysis finishes within the approximately 1,000 ms tuning guideline.

### Real-Bash equivalence

For the explicitly supported subset, execute curated and generated scripts
under `env -i` with a known non-secret environment. Temporary `PATH` command
shims record NUL-delimited argv and exported child environments. Compare that
trace and final modeled shell bindings to the walker result. Unsupported
constructs receive dedicated conservative-degradation tests rather than being
treated as equivalence failures.

The fixtures, generator boundary, and trace format must be reusable for future
differential fuzzing over a broader Bash language subset. Initial verification
does not require arbitrary-Bash fuzzing.
