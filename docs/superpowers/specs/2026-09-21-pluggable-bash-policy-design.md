# Pluggable Bash Policy Sources and Terminating Policy DSL

**Status:** Approved design

## Summary

Safety-core will keep Bash parsing, symbolic execution, wrapper expansion, and
bounded traversal in the core while moving command authorization into
source-loaded policies. Policies will no longer be identified by a closed set
of profile names. Loading a policy source enables it, and its canonical source
path provides provenance.

The initiative has three deliberate stages:

1. Introduce a generic trusted-code policy API and migrate all current Bash
   policies behind it.
2. Define and implement a terminating JSON policy DSL based on a deterministic
   consuming register machine.
3. Port the complete current Bash policy inventory, including execution-gap
   guards, to the DSL while retaining the code API for future advanced
   policies.

Global configuration is authoritative and directly usable without Nix. Nix is
an optional management and distribution layer that installs policy files and
generates the same configuration. Trusted global configuration may load code
or DSL policies. Permitted project configuration may initially add only DSL
policies.

## Goals

- Provide a substantially stronger permission language than harness-native
  prefix, glob, or regular-expression rules.
- Keep shell execution semantics and reachability analysis in one core engine.
- Make command policies independently loadable without editing central profile
  unions, registration tables, or adapter policy switches.
- Compose overlapping policies without registration-order or profile-priority
  effects.
- Support project-specific additive policies under global operator control.
- Let policies inspect complete modeled invocation values, including the entire
  modeled environment.
- Give the DSL no arbitrary filesystem, process, network, clock, module-loading,
  or mutation capabilities.
- Make DSL termination in finite time and memory a property of every valid
  program, established by cheap static validation.
- Provide production-equivalent `validate` and `explain` tooling.
- Migrate the complete current Bash policy inventory to the DSL.

## Non-goals

- Treating safety-core as a strong sandbox or security boundary.
- Letting policies alter Bash traversal, schedule child execution, or define
  wrapper semantics.
- Project-local code policies in the initial design.
- Cross-invocation, cross-tool-call, or session-persistent policy state.
- Unifying direct Read, WebFetch, or arbitrary harness tool policies in the
  first policy API.
- Moving the LLM judge into the DSL.
- Moving audit-file persistence or any other side effect into policies.
- Preserving the legacy `profiles.json` schema.
- Resolving execution-analysis TOCTOU without an execution broker.

## Design principles

### Configuration selects sources, not policy IDs

There is no policy catalogue and no enabled-policy ID list. A policy source
reference means “load and enable this policy.” A canonical source path is used
for diagnostics, traces, duplicate detection, and lifecycle tracking.

The canonical path is the policy identity. The source digest is integrity and
version metadata, not identity. Two different canonical paths containing
identical bytes are distinct policies; repeated references resolving to the
same canonical path load one policy.

A future bundle is only a distribution abstraction that expands into ordinary
source references. It does not introduce new evaluation semantics.

### Policy definitions are complete

The generic API has no `configSchema` or arbitrary parameter channel. Constants,
allowlists, grammars, and predicates are content of the policy source itself.
Materially different behavior is represented by another complete source file.

Nix or another management tool may generate a complete policy source containing
operator-selected constants and then add its path to configuration. Direct
non-Nix users can author the equivalent source themselves.

### Structured values are semantic, not redacted

Policies receive actual modeled values. Safety does not come from sanitizing
policy input. It comes from restricting what a DSL program can do with the
input.

Commands are assumed not to contain passwords and may be logged. The DSL may
interpolate any supplied invocation or environment value into a returned
reason, suggestion, or audit field. Those outputs return to the core; the DSL
has no direct output or persistence capability.

Unknown runtime values remain explicit unknown values. The engine must never
invent a string for an unresolved expansion.

## Architecture

```text
authoritative global config
          +
permitted project config
          |
          v
policy source loader ---- startup validation/compilation
          |
          v
immutable session policy set
          |
          v
Bash parser and symbolic execution engine
          |
          +---- normalized invocation events
          +---- execution-gap events
          |
          v
all selected guard and permission policies
          |
          v
per-event decision algebra
          |
          v
whole-request coverage decision + explain trace
          |
          v
harness adapter
```

### Core responsibilities

The core owns:

- Bash parsing and syntax diagnostics.
- Word expansion and explicit known/unknown values.
- Shell variables, functions, assignments, branches, and process isolation.
- Wrapper and nested-command semantics.
- Reachable execution enumeration.
- Analysis budgets and finite traversal.
- Executable lookup and path identity evidence.
- Policy event construction.
- Policy selection, composition, and complete-coverage proof.
- Configuration and source loading before the agent loop.
- Structured decision traces.

### Policy responsibilities

A policy:

- Selects relevant immutable engine events.
- Parses and classifies one invocation at a time.
- Returns `allow`, `deny`, `defer`, or `ignore` as permitted by its layer.
- Supplies reasons, suggestions, and structured audit values.
- Does not mutate the engine or retain state between invocations.

### Structural execution remains core-owned

Shells, `eval`, `source`, `env`, `time`, `find -exec`, `xargs`, privilege
wrappers, and similar commands may alter which child commands execute. Their
structural semantics remain built into the core.

For example, the core recognizes `time -p <command>`, applies the wrapper’s
argument grammar, and emits the child invocation. The policy DSL classifies
the emitted invocation; it does not learn to recurse through `time`.

## Policy events

### Invocation event

Each reachable authorization-relevant command produces an immutable
`InvocationView` containing at least:

```ts
interface InvocationView {
  readonly kind: "invocation";
  readonly executable: ExecutableIdentity;
  readonly argv: readonly ModeledValue[];
  readonly environment: ModeledEnvironment;
  readonly assignments: AssignmentFacts;
  readonly redirects: readonly RedirectView[];
  readonly provenance: ExecutionProvenance;
  readonly pipeline: PipelineContext;
  readonly processEffect: ProcessEffect;
  readonly source: SourceContext;
}
```

The complete modeled environment is available, including actual values of
known inherited variables. Unknown and absent bindings remain distinct.

### Execution-gap event

When the engine cannot structurally materialize a possible child execution, it
emits a finite event describing the known route and reason:

```ts
interface ExecutionGapView {
  readonly kind: "execution-gap";
  readonly reason: ExecutionGapReason;
  readonly provenance: ExecutionProvenance;
  readonly source: SourceContext;
}
```

An execution gap always makes complete permission proof impossible. Guard
policies may additionally deny specific unsupported routes. This preserves
policies such as the current unsupported-shell-source guard without embedding
their decisions in the execution engine.

## Policy layers and decisions

### Layers

- A **guard** may return `deny` or `ignore`.
- A **permission** policy may return `allow`, `deny`, `defer`, or `ignore`.

A guard returns `ignore` when it finds no violation. It must never return
`allow`, because successful restriction checks do not grant permission.

### Per-event composition

For each reachable invocation:

1. Evaluate every selected policy.
2. If any policy returns `deny`, the invocation is denied.
3. Otherwise, if at least one permission policy returns `allow`, the invocation
   is covered.
4. Otherwise the invocation is uncovered.

`defer` records that a policy recognized but could not approve the form. It
does not veto an allow from another policy. A policy that must prevent an
overlapping allow must return `deny`.

Policy and source ordering never affect the result.

The same deny rule applies to every policy event. A guard denial produced while
evaluating an execution-gap event denies the request even though the event is
not an invocation.

### Whole-request composition

- A denial on any invocation or execution-gap event denies the whole request.
- An allow requires complete engine analysis and coverage of every reachable
  authorization-relevant invocation.
- Any execution gap, engine analysis failure, or uncovered invocation makes
  the request defer to the harness permission boundary.
- The core may mark modeled shell-internal structural operations intrinsically
  covered; unknown external execution is never intrinsically covered.

This replaces profile ownership, policy priority, and the requirement that one
legacy profile cover an entire request. Different policies may cover different
commands in one compound Bash request.

## Source formats and trusted code API

### One policy per source

Each referenced source defines exactly one policy. Exact duplicate canonical
source references are loaded once and reported in validation output. Different
sources may intentionally overlap.

Initial source forms are:

- `*.policy.mjs`: trusted code policy; global configuration only.
- `*.policy.json`: declarative DSL policy; global or permitted project
  configuration.

File extensions select the loader and are validated exactly. Project
configuration cannot reference code policy files in the initial design.

### Trusted code policy contract

A code policy exports one frozen policy definition:

```ts
interface BashPolicy {
  readonly apiVersion: 1;
  readonly layer: "guard" | "permission";
  readonly select: readonly BashPolicySelector[];
  evaluate(event: BashPolicyEvent): BashPolicyDecision;
}
```

The loader, not the policy, attaches canonical source path and source digest.
Code policies are trusted installed code and are not subject to the DSL’s
termination proof. Import, initialization, and runtime exceptions are fatal.

### Selector semantics

A selector is an OR-list over event selectors. Initial selectors support:

- All invocation events.
- Exact executable basenames.
- Exact selected executable paths.
- Exact canonical executable targets.
- Exact membership in the observed resolution chain.
- Execution-gap events, optionally restricted by exact gap kind.

Top-level executable selectors do not support glob, prefix, substring, or
regular-expression matching. Richer predicates remain inside the policy
machine and require a concrete use case before being promoted into dispatch
selectors.

An unavailable path projection does not match. A policy that must act on path
uncertainty selects a broader known identity, such as basename, and tests the
resolution status inside evaluation.

## Authoritative configuration

### Global configuration path

The runtime chooses the global configuration base in this order:

1. `$SAFETY_CORE_CONFIG_HOME/safety-core/config.json`
2. `$XDG_CONFIG_HOME/safety-core/config.json`
3. `$HOME/.config/safety-core/config.json`

Selection depends on whether a variable is set, not whether the resulting file
exists. Once a higher-precedence variable selects a location, a missing file is
fatal and does not fall through. Config-home variables and `HOME` must be
non-empty absolute paths; empty or relative values are fatal.

The global file has this initial shape:

```json
{
  "version": 1,
  "policies": [
    "/installed/policies/secret-files.policy.mjs",
    "/home/user/.config/safety-core/policies/company.policy.json"
  ],
  "projectPolicies": {
    "mode": "allowlisted",
    "allowedRoots": [
      "/home/user/work/acme"
    ]
  },
  "bashAnalysis": {
    "maxFunctionDepth": 128,
    "maxNestedScriptDepth": 64,
    "maxSteps": 7500,
    "maxWorkItems": 10000
  }
}
```

`projectPolicies.mode` is one of:

- `disabled`: never inspect project configuration.
- `allowlisted`: load project configuration only when its canonical root is an
  exact member of `allowedRoots`.
- `all`: load the nearest project configuration without a root allowlist.

Relative global policy references resolve from the directory containing the
global configuration file. Absolute references remain absolute. All paths are
canonicalized before loading.

### Project configuration

The nearest ancestor of the harness working directory containing
`.safety-core/config.json` is the candidate project root. Parent project
configurations do not cascade.

An allowed project file has this shape:

```json
{
  "version": 1,
  "policies": [
    "policies/kubectl-read.policy.json",
    "/shared/policies/project-conventions.policy.json"
  ]
}
```

Relative project references resolve from the project root. Absolute references
are permitted. Every referenced project source must be a DSL source.

Project policies are strictly additive. They cannot remove, replace, shadow,
or alter globally loaded sources.

“Additive” intentionally permits an authorized project permission policy to
expand automatic authorization: it may cover an invocation that global
permission policies leave uncovered. Every global and project guard still
applies, and any denial remains dominant. The global project-policy mode and
canonical-root allowlist are therefore an authorization trust boundary, not
only a source-discovery preference.

### Nix management

The configuration files are authoritative; Nix is optional. The Home Manager
module exposes an option corresponding to every configuration field and may
provide helpers that:

- Install code or DSL policy files.
- Normalize their installed paths.
- Add those paths to generated configuration.
- Generate complete policy files containing operator-selected constants.

The same runtime behavior must work for manually managed files.

### Startup lifecycle

Global configuration, applicable project configuration, and every policy
source are resolved, parsed, validated, imported, and compiled before the
agent loop begins. The resulting policy set is immutable for the session.
Changes require a session restart.

The following are fatal startup failures:

- Missing or malformed global configuration.
- Invalid applicable project configuration.
- Missing source files.
- Disallowed project source types.
- Unsupported source or policy API versions.
- Invalid DSL syntax, types, machine structure, or built-in use.
- Code policy import or initialization failures.

A runtime policy exception is also fatal. Adapters must not silently fall back
to native permission behavior after policy-platform failure.

Adapters validate at their earliest lifecycle boundary:

- OpenCode plugin initialization.
- Pi session startup.
- Claude session-start validation, with command hooks retaining defensive
  validation because hooks execute in isolated processes.

OpenCode and Pi retain the loaded immutable policy objects in their session
process. Claude’s session-start hook writes a session manifest keyed by
`session_id`, containing the selected project root, canonical source list, and
digest of every configuration and policy source. Each isolated command hook
requires that manifest and verifies the same bytes before loading policy code;
a changed or missing source is fatal rather than becoming a live reload. Code
policy sources must therefore be self-contained bundled modules without
relative runtime imports. A new Claude session creates a new manifest.

After any runtime policy exception, an in-process adapter marks its policy
runtime poisoned, rejects the current tool call, reports the source and error,
and rejects every later policy-controlled call in that session. Claude hooks
exit with the harness’s hard-failure status; subsequent hooks continue to fail
against the session manifest. No adapter maps such failure to neutral or
native-permission fallback.

## Executable identity

### Identity model

Each invocation carries:

```ts
interface ExecutableIdentity {
  readonly spelling: {
    readonly token: ModeledValue;
    readonly basename: ModeledValue;
    readonly qualification: "bare" | "relative-path" | "absolute-path" | "unknown";
  };
  readonly lookup: ExecutableLookup;
  readonly resolution: ExecutableResolution;
}
```

`qualification` is `unknown` whenever unresolved executable spelling prevents
the engine from proving which lexical form applies.

Lookup distinguishes a directly supplied path from an ordered PATH-selected
candidate. Complete resolution records the selected absolute path, every
observed pathname/symlink stage, and the final canonical target. Incomplete
resolution preserves the observed prefix and a typed reason.

### Bare executable lookup

For a bare executable, the core attempts shell-compatible lookup using the
invocation’s modeled effective PATH and working directory.

- PATH entries are processed in order.
- Empty PATH entries mean the effective working directory.
- Relative entries require a known working directory.
- An unknown/erroring earlier entry prevents claiming that a later candidate
  was selected.
- Functions, builtins, and structurally modeled launcher behavior take
  precedence where the engine models them.
- A filesystem resolver is injected so tests and offline replay do not
  accidentally consult unrelated host state.

### Symlink resolution

Resolution processes pathname components in filesystem order, including
directory symlinks and relative symlink targets. It does not lexically collapse
paths in a way that changes kernel symlink semantics.

Incomplete reasons include:

- unknown PATH
- unknown working directory
- not found
- permission failure
- I/O failure
- changed during resolution
- broken symlink
- symlink loop
- symlink-depth exhaustion
- unsupported filesystem behavior

Path selectors are exact and explicit about projection:

- `selected-path`
- `canonical-target`
- `chain-contains`

Policies may require conjunctions in machine logic, for example both an exact
selected profile path and an exact immutable store target. A basename policy
may deliberately allow when path resolution is unavailable; that is name-based
classification, not implementation proof.

### Known limitations and failure cases

The implementation and user documentation must explain:

- Resolution is an observation during analysis, not a guarantee about later
  execution.
- Symlinks, PATH directories, files, permissions, credentials, mounts, and
  namespaces can change between analysis and execution.
- Matching any chain element is unsafe as the sole basis for trusting a final
  executable target.
- Canonical-target-only matching ignores the route used to reach the target.
- Nix profile and generation links are mutable even when final store targets
  are immutable.
- Directory symlinks, relative targets, and `..` have kernel-order semantics.
- Hard links and bind mounts create aliases absent from a symlink chain.
- A resolved executable may itself be a wrapper, shim, interpreter, plugin
  host, or helper launcher.
- Basename matching can classify a different implementation with the same
  name.
- Shell command hashes, functions, builtins, launchers, and effective identity
  can differ from a simple PATH model.
- Without executing a pinned file descriptor in the same environment and
  namespace, safety-core cannot guarantee that the observed file is executed.
- Even descriptor-based execution would not automatically pin shebang
  interpreters, loaders, libraries, configuration, plugins, or child helpers.

Closing these races requires an execution-broker architecture and is outside
this initiative.

## Formal DSL model

### Deterministic Consuming Register Machine

The DSL compiles to a Deterministic Consuming Register Machine (DCRM):

\[
M = (Q, q_0, R, F, T, D)
\]

where:

- \(Q\) is a finite set of states.
- \(q_0\) is the unique initial state.
- \(R\) is a finite set of typed registers.
- \(F\) is a finite set of context folds.
- \(T\) is a deterministic set of consuming transitions.
- \(D\) constructs terminal decisions.

Runtime state is:

\[
(q, i, j, r, f, V)
\]

where \(i\) is a forward-only argv-token cursor, \(j\) is either absent or a
forward-only byte cursor within the current short-option cluster, and \(V\) is
the immutable finite policy event.

A general runtime pushdown stack is intentionally omitted. Current command
paths are regular, and actual nested execution is already core-owned.
Reusable source fragments are acyclic compile-time expansion, not runtime
calls. A constrained stack may be reconsidered only after a concrete policy
cannot be represented within the DCRM.

### Authored JSON grammar

The authored JSON is a typed convenience surface that desugars into the DCRM.
The top-level grammar is:

```text
Policy        := {
  language,
  layer,
  select,
  registers?,
  folds?,
  options?,
  start,
  states
}

Layer         := "guard" | "permission"
Selector      := InvocationSelector | GapSelector
Register      := Bool | Enum | Count | InputRef | FixedTuple
State         := { cases, default, end }
Case          := { when, action }
Action        := Transition | Terminal
Transition    := { consume, set?, fold?, next }
Terminal      := { decision, reason?, suggestion?, audit? }
Decision      := "allow" | "deny" | "defer" | "ignore"
```

The normative specification defines each object field, legal combinations,
static type, evaluation order, and desugaring. Unknown keys are rejected.

### Registers

Registers are statically declared and fixed in number. Supported initial types
are:

- Boolean.
- Finite enum.
- Saturating counter `count<k>` where `k` is a source literal.
- Optional reference to an input word or supplied context value.
- Fixed tuple of supported register types.

Input references point into immutable input and do not copy strings. The DSL
has no dynamically growing list, map, set, stack, or synthesized string value.

### Options

Option declarations provide a standard total parser for:

- Exact short and long names.
- Required, optional, or absent values where the selected CLI grammar permits
  them.
- Separate values.
- Attached short values.
- `--long=value` values.
- Short clusters.
- Repeatability and duplicate handling.
- Conflicts.
- `--` end-of-options handling.
- Unknown or missing values.
- State-local or machine-wide availability.

Machine-wide options desugar to consuming cases in every declared state. This
allows position-independent forms such as:

```text
kubectl -n team get pods
kubectl get -n team pods
kubectl get pods --namespace=team
```

without enumerating argument permutations.

### Transition semantics

- Before `--`, applicable option declarations are evaluated in declaration
  order, followed by state cases in source order. After `--`, only state cases
  are evaluated.
- The first matching option or state case is chosen.
- Its guard is evaluated against the pre-transition state. Option decoding and
  required-value validation then establish captures. Register/fold updates are
  applied simultaneously from that pre-transition state, input is consumed,
  and control moves to the declared next state. A terminal action returns
  immediately without an implicit consume or update.
- Every nonterminal step consumes at least one whole argv token or, while an
  option cluster is active, at least one byte of that finite token.
- A consuming option transition may consume a statically bounded number of
  tokens, such as an option and its separate value.
- Every state defines terminal behavior for end-of-input and unmatched input.
- There is no cursor rewind, computed jump, user loop, recursion, runtime
  policy call, or nondeterministic branching.

The progress measure is the total number of unconsumed argv token boundaries
plus unconsumed argv bytes. Every nonterminal machine step strictly decreases
that finite natural-number measure.

### Context folds

A fold traverses exactly one finite supplied collection and uses a fixed-size
accumulator. Initial folds are:

- `any(predicate)`
- `all(predicate)`
- `firstRef(predicate)`
- `lastRef(predicate)`
- `countUpTo(k, predicate)`

Folds cannot nest, invoke another collection scan, or run from inside each argv
transition. Each declared fold is evaluated at most once per policy event and
its result is cached. These restrictions prevent repeated context scans from
being hidden inside argv processing.

### Expressions and built-ins

Expressions contain literals, register references, current-token references,
context references, Boolean operations, comparisons, finite-set membership,
and calls to a closed versioned built-in catalogue.

Built-ins must be total and have documented time and output-size bounds.
Initial categories include:

- Exact string equality and finite-set membership.
- Case normalization with fixed semantics.
- Prefix, suffix, and substring tests.
- Basename and lexical path-component operations.
- Fixed-delimiter split with a constant component index.
- Integer parsing and bounded comparison.
- Safe glob matching.
- Linear-time regular expressions without backreferences or lookaround.
- URL, host, and repository-identifier parsing.
- Environment lookup preserving known, unknown, and absent.
- Redirect, assignment, provenance, pipeline, and process-effect predicates.
- Kubernetes resource and GitHub endpoint normalization needed by migrated
  policies.

Before implementation, the normative language specification enumerates the
exact initial built-ins and maps each one to at least one current policy being
migrated. Categories above are not permission to add speculative built-ins.

Built-ins cannot access ambient process state, locale-dependent services,
filesystem state, clocks, randomness, network data, or modules. Filesystem and
executable identity facts must come through `InvocationView`.

Policy-specific host callbacks are forbidden. A reusable operation needed by a
policy becomes a documented language built-in only after its totality,
complexity, and general semantics are reviewed.

### Diagnostics and audit values

Terminal outcomes may use finite templates containing literal fragments and
references to any supplied input or register value. Arbitrary supplied values,
including environment values, may be interpolated.

Templates cannot loop or call collection scans. Audit values use finite JSON
objects whose structure is present in the source and whose leaves are literals
or finite input/register references.

## Static validity

A DSL policy is accepted only when validation establishes all of the following.

### Structural and type validity

- Exact supported language version.
- Only known fields and AST node kinds.
- One start state.
- Unique state, register, fold, and option names.
- All references resolve.
- Register initializers and assignments are type-correct.
- Every state has unmatched-input and end-of-input behavior.
- Guard policies contain no `allow` terminal.
- Every builtin exists at the selected language version and receives values of
  the required type.
- Policy size, state count, transition count, literal-table size, regex program
  size, and template size remain within documented fixed implementation caps.

### Progress validity

- Every nonterminal transition consumes input.
- Every short-cluster microstep consumes a byte.
- Consumption counts are statically bounded.
- No input rewind or computed transition target exists.
- Source-fragment expansion is acyclic and bounded before runtime.
- Every fold scans one finite collection once and folds do not nest.
- No dynamically allocated policy collection exists.

Validation is linear in compiled policy size, excluding the separately bounded
linear compilation cost of safe regular expressions.

## Termination and finite-resource proof

Let:

- \(P\) be compiled policy size, including literal and regex programs.
- \(A\) be total argv token and byte size.
- \(C\) be the size of the remaining finite modeled context.
- \(B = A + C\).

### Termination

1. `InvocationView` is finite.
2. The number of states and registers is finite.
3. Every nonterminal step consumes at least one whole token or at least one byte
   from an active finite short-option cluster.
4. Each context fold consumes one element from one finite collection and cannot
   nest.
5. Every state terminates at EOF.
6. Every built-in is total.
7. The language has no recursion, rewind, computed jumps, or user loops.

Therefore every validator-accepted policy terminates for every finite policy
event.

### Time

Ordered cases may inspect up to \(O(P)\) predicates for each consumed input
unit. A predicate may apply a linear-time total builtin to an operand of size up
to \(O(B)\). Each declared context fold scans one finite collection once and is
cached, but transition predicates may intentionally compare current argv words
with finite context values.

Worst-case policy evaluation is therefore:

\[
O(PB^2)
\]

This conservative polynomial bound follows directly from the language rules;
individual policies and common option grammars are expected to be closer to
linear. Performance tests enforce the formal bound and practical startup/tool
latency budgets without claiming an unsupported linear worst case.

### Memory

- Compiled policy storage is \(O(P)\).
- Mutable runtime registers and fold accumulators are \(O(P)\).
- Immutable engine-owned input is \(O(B)\).
- Input references avoid copying values into registers.
- A finite diagnostic template may repeat finite input references, so returned
  output is bounded by \(O(PB)\).

Total memory, including fully materialized output, is finite and bounded by
\(O(PB)\); evaluator working memory excluding returned output is \(O(P+B)\).

## JSON policy example

This abbreviated policy illustrates position-independent namespace parsing:

```json
{
  "language": "safety-core/bash-policy-v1",
  "layer": "permission",
  "select": [
    {
      "executable": {
        "projection": "basename",
        "equals": "kubectl"
      }
    }
  ],
  "registers": {
    "namespace": {
      "type": "inputRef",
      "initial": null
    }
  },
  "options": {
    "namespace": {
      "names": ["-n", "--namespace"],
      "value": "required",
      "forms": ["separate", "attachedShort", "equalsLong"],
      "availableIn": "*",
      "set": {
        "namespace": { "ref": "option.value" }
      }
    }
  },
  "start": "command",
  "states": {
    "command": {
      "cases": [
        {
          "when": { "wordEquals": "get" },
          "action": {
            "consume": "word",
            "next": "get-resource"
          }
        }
      ],
      "default": { "decision": "ignore" },
      "end": { "decision": "ignore" }
    },
    "get-resource": {
      "cases": [
        {
          "when": {
            "call": "wordInAsciiCaseInsensitiveSet",
            "args": [
              { "ref": "word" },
              ["secret", "secrets"]
            ]
          },
          "action": {
            "decision": "defer",
            "reason": ["Resource ", { "ref": "word" }, " requires review"]
          }
        },
        {
          "when": { "wordKnown": true },
          "action": {
            "consume": "word",
            "next": "get-tail"
          }
        }
      ],
      "default": { "decision": "defer" },
      "end": { "decision": "defer" }
    },
    "get-tail": {
      "cases": [
        {
          "when": { "wordAny": true },
          "action": {
            "consume": "word",
            "next": "get-tail"
          }
        }
      ],
      "default": { "decision": "defer" },
      "end": {
        "decision": "allow",
        "reason": ["kubectl get is permitted in namespace ", { "ref": "namespace" }]
      }
    }
  }
}
```

The normative grammar may use more explicit nodes than this example after
desugaring, but it must preserve the demonstrated semantics without argument
permutation enumeration.

## Explainability and authoring tools

The core returns a structured trace containing:

- Parsed execution structure.
- Every reachable policy event.
- Executable identity and resolution status.
- Every selected source.
- Every source decision and diagnostic.
- Per-invocation aggregate.
- Final request aggregate.
- Analysis completeness and consumed budgets.

Adapters consume the aggregate and may show only actionable summaries. They do
not reconstruct policy reasoning.

The production package provides:

```text
safety-core validate [--cwd PROJECT]
safety-core explain [--cwd PROJECT] [--json] -- <bash source>
```

`validate` runs the production configuration resolver, source loader, code
importer, DSL validator, and compiler. It exits nonzero with source-positioned
diagnostics on any failure.

`explain` uses the production parser, engine, resolver, policy set, and decision
algebra. Human output is optimized for policy authors; JSON output is stable
enough for tests and external tooling within one declared trace schema version.

Outputs may contain complete command and modeled environment values. Operators
must treat explain output and policy-generated logs according to the
sensitivity of their supplied environment.

## Migration

### Required current-policy inventory

The full DSL port includes every current Bash policy represented by these
evidence families and their command-specific helpers:

- `secret-read`, including reader and redirect checks.
- `github-http`.
- `kubectl`, including audit-value production.
- `unsupported-shell-source`, evaluated over execution-gap events.
- `gh-api`.
- `gh-pr-create`.
- `generic-read-only`, including Git, Tea, checksum, and wrapper-related
  classifiers.
- `gh-read-only`.
- `helm-read-only`.
- `strict-read-only`, including every currently mapped executable.

There is no approved current Bash policy exception left in code at the end of
the initiative. Structural handlers, the LLM judge, audit persistence, and
direct Read/WebFetch handling are not Bash policy classifiers and remain in
their previously specified layers. The retained code-policy API is for future
advanced policies, not for silently exempting difficult current policies from
the DSL migration.

### Phase 1: formal contract

- Specify `InvocationView` and execution-gap events.
- Specify source loading and configuration.
- Specify the DCRM grammar, types, desugaring, built-ins, and proof.
- Specify executable identity and limitations.

### Phase 2: generic code-policy platform

- Replace closed policy-name evidence with source provenance.
- Replace hard-coded profile registration and ownership with loaded sources.
- Implement per-invocation decision composition.
- Add global configuration and fatal startup validation.
- Add `validate` and `explain` over code policies.

### Phase 3: code-first behavior migration

- Package every existing Bash guard and profile as a trusted code source.
- Move policy-specific adapter presentation into generic structured decisions.
- Differentially compare old and new behavior.
- Cut over adapters and remove `profiles.json` support atomically.

### Phase 4: executable identity

- Add modeled PATH lookup and structured resolution evidence.
- Inject filesystem resolution for deterministic tests and replay.
- Add explicit path projection selectors.
- Document known limitations and failure cases.

### Phase 5: DSL and project policies

- Implement JSON parsing, static validation, desugaring, and evaluation.
- Implement DSL source loading globally.
- Implement nearest-project discovery, global trust modes, and additive
  project-local DSL loading.
- Extend `validate` and `explain` to DSL sources.

### Phase 6: full Bash-policy port

- Port the complete required current-policy inventory to DSL, including
  invocation and execution-gap classifiers.
- Keep each code implementation in differential shadow tests until parity or an
  intentionally stronger result is approved.
- Convert current command inventories and allowlists into finite DSL tables or
  total general built-ins.
- Remove migrated code implementations.
- Retain the code policy API for advanced future policies.

### Phase 7: packaging and review

- Complete direct-configuration documentation.
- Complete Nix options and policy-installation helpers.
- Run all verification layers and performance checks.
- Conduct a frontier-model adversarial review.
- Present and discuss that review with the operator before making corrections.

## Verification

Every changed subsystem requires both focused unit tests and generated/property
tests: configuration, source loading, lifecycle snapshots, event construction,
decision aggregation, executable resolution, DSL validation/evaluation,
adapters, packaging, and authoring tools. Final verification runs the complete
repository test suite, packaged command-profile tests, Nix module evaluations,
and flake/package checks rather than only new focused tests.

### Decision algebra

Property tests must prove:

- Policy and source ordering cannot change a result.
- Any denial dominates every allow, defer, or ignore.
- At least one permission allow covers an invocation when no denial exists.
- Every reachable invocation must be covered for request allow.
- Guards cannot grant permission.
- Execution gaps and engine failures prevent request allow.

### Configuration and sources

Tests cover:

- Global path precedence.
- Direct non-Nix configuration.
- Nix-generated equivalent configuration.
- Relative and absolute source resolution.
- Canonical duplicate handling.
- Disabled, allowlisted, and all-project modes.
- Exact canonical project-root matching.
- Nearest-project selection without ancestor cascading.
- Project DSL-only enforcement.
- Strictly additive project behavior.
- Fatal startup for every malformed, missing, incompatible, or throwing source.
- Generated path/configuration cases proving canonicalization, source ordering,
  and project discovery cannot alter decision semantics.

### Executable identity

Unit and property tests use an injected filesystem transcript and cover:

- Ordered PATH candidates.
- Empty and relative PATH entries.
- Unknown earlier entries hiding later candidates.
- Direct relative and absolute paths.
- Single and multi-hop symlinks.
- Directory symlinks.
- Relative symlink targets.
- `..` after symlink traversal.
- Broken links, loops, and depth exhaustion.
- Permission and I/O failures.
- Mutation during resolution.
- Nix profile-to-generation-to-store chains.
- Selected/canonical/chain projection conflicts.
- Definite denial preservation under incomplete resolution.
- Added ambiguity never creating a path-dependent allow.
- Exact matching never degrading into prefix, glob, regex, substring, or
  case-folded matching.

### DSL validator and evaluator

Tests cover:

- Every grammar node and static type rule.
- Rejection of unknown fields and unsupported versions.
- Rejection of non-consuming transitions, rewind, recursion, dynamic jumps,
  nested folds, dynamic collections, and non-total built-ins.
- Generated validator-accepted policies always terminating under generated
  finite invocation views.
- Measured scaling consistent with the \(O(PB^2)\) worst-case bound, plus
  tighter practical latency budgets for representative policies.
- Position-independent options without permutation enumeration.
- Separate, attached, equals, cluster, duplicate, conflict, missing-value, and
  `--` semantics.
- Known, unknown, and absent values.
- Arbitrary input interpolation in finite diagnostics.
- Synthetic canary values proving argv and the entire modeled environment reach
  code and DSL policies unchanged and may be reproduced exactly in diagnostics
  and explain output.
- Explain-trace determinism and completeness.

### Migration parity

Every migrated policy retains or intentionally strengthens existing unit and
property coverage, including:

- Secret file and redirect guards.
- Direct GitHub HTTP restrictions and steering.
- Kubectl restrictions and audit observations.
- Generic, Git, GitHub, Helm, and strict read-only command policies.
- GitHub API method and endpoint classification.
- Pull-request creation restrictions and allowlists.
- Argument ordering, aliases, environment routes, wrappers, and unknown values.
- Historical Bash replay where available.

### Integration and performance

- Claude, OpenCode, and Pi startup behavior.
- Fatal startup diagnostics.
- Runtime policy exceptions poisoning/rejecting each adapter session as
  specified, with no native-permission fallback.
- Native permission mapping.
- Session-immutable policy snapshots.
- Packaged code and DSL source loading.
- Direct and Nix-managed installations.
- Large policy sets, large finite tables, long argv, and large modeled
  environments.
- Full repository, Nix evaluation, flake, and packaged-runtime verification
  gates.

The required frontier-model adversarial report is presented to and discussed
with the operator before any correction prompted by that report is made.

## Alternatives rejected

### Closed profile registry

Keeping named profiles and adding plugin registration would preserve central
ownership, priority, and schema coupling. Source-loaded complete policies remove
that duplication and better support project definitions.

### Universal declarative IR before a code boundary

Forcing every current policy directly into an unproven IR would couple engine
refactoring to language invention. Code-first migration validates the event and
decision boundary before the DSL replaces implementations.

### Runtime plugin host or policy subprocesses

An isolated plugin ecosystem adds discovery, serialization, lifecycle, and
compatibility infrastructure before the policy semantics are stable. Trusted
global code sources and capability-limited project DSL are sufficient here.

### OPA/Rego

OPA is powerful but broader than required. Recursion, comprehensions, joins,
and evolving language semantics complicate the desired cheap static termination
and resource argument.

### Datalog

Finite Datalog can guarantee termination, but recursive closure and joins add
unnecessary polynomial behavior for sequential argv grammars and complicate
captures and diagnostics.

### JSON expression trees with unrestricted array combinators

Nested map/filter/all constructs can hide \(O(n^k)\) evaluation. The consuming
machine and non-nested finite folds expose progress and cost directly.

### Regular-expression policy lists

Regex lists cannot robustly model paired option values, order independence,
short clusters, duplicates, `--`, command paths, environment conditions, or
resolved executable identity without reconstructing lossy command strings.

### General pushdown automaton

A runtime stack is unnecessary for flat resolved invocation grammars and adds
proof and validation complexity. Core already owns nested execution semantics.

### Fuel-limited general-purpose code as the DSL

Fuel bounds stop execution operationally but do not make valid policies
intrinsically total or easy to reason about. General code also exposes a much
larger capability and compatibility surface.

## Success criteria

The initiative is complete when:

- Core contains execution semantics but no implicit command policies.
- Every policy is loaded from an explicit source file.
- Global and permitted project configuration behave as specified.
- Startup fails before the agent loop for invalid configuration or sources.
- Policy composition is order-independent and follows the documented algebra.
- The DCRM grammar, validator, semantics, and finite-resource proof are
  implemented and documented.
- The complete required current-policy inventory, including execution-gap
  guards, is authored in DSL and passes differential parity or approved
  stronger-behavior tests.
- Exact executable basename and explicit path-projection selectors work with
  documented resolution limits.
- `validate` and `explain` use production code paths.
- Direct configuration and optional Nix management both pass integration tests.
- Unit, property, equivalence, replay, performance, and harness tests pass.
- The adversarial frontier-model review has been presented and discussed before
  resulting corrections are made.
