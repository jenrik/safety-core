# DCRM policy languages v1 and v2

`safety-core/bash-policy-v1` and its additive successor
`safety-core/bash-policy-v2` are JSON-only deterministic consuming register
machine (DCRM). It classifies one immutable policy event. It cannot call host
code, mutate the event, access files/processes/network/clock/modules, allocate
policy-defined dynamic collections, retain state across events, recurse, rewind input, or
compute a jump target.

The loader for JSON sources is introduced separately. This document specifies
the source document accepted by `parsePolicyDocument`,
`validatePolicyDocument`, and `compilePolicyDocument`. Existing v1 documents
retain their exact grammar and builtin catalogue. The intra-word facilities
below are available only to v2 documents.

## Document

Every object is closed: an unknown member is an error. The language value is
exactly one of the two version strings above; compatible prefixes and other
versions are not accepted. JSON text is scanned for duplicate object keys
before it is decoded, so a later declaration cannot silently replace an
earlier one.

```text
Policy := {
  language, layer, select, registers?, folds?, options?, fragments?, start, states
}
layer := "guard" | "permission"
State := { fragments?, cases, default, end }
Case := { when, action }
Transition := { consume: "word" | "byte" | "restOfWord", next, set?, fold? }
Terminal := { decision, reason?, suggestion?, audit?, capture?, fold? }
```

`start` and every transition `next` name one declared state. Names are ASCII
identifiers (`[A-Za-z][A-Za-z0-9_]*`) and are unique by their JSON object key.
Each state has a terminal `default` for unmatched input and a terminal `end`
for EOF. `allow` and `deny` require a finite `reason` template. A `guard` may
return `deny`, `defer`, or `ignore`; it cannot return `allow`. `deny` and
`defer` may attach a source-fixed audit object, including `{ "ref": "event" }`
when adapters require the complete immutable policy event.

`select` contains one or more exact selectors. A source is selected when any
selector matches, allowing a finite family of exact executable basenames without
falling back to all-invocation evaluation.

```json
[{ "kind": "invocation" }]
```

```json
[{ "kind": "execution-gap", "reason": "unsupported-shell-source" }]
```

```json
[{ "executable": { "projection": "basename", "equals": "kubectl" } }]
```

Executable projections are exactly `basename`, `selected-path`,
`canonical-target`, and `chain-contains`. They are exact, case-sensitive
matches; rich matching belongs in a machine expression.

## Registers and expressions

Registers are fixed declarations. `bool`, `enum`, `count`, `inputRef`, and a
fixed `tuple` are the complete v1 domains; v2 additionally has `location`.
`count` has a positive literal `max` and an in-range literal `initial`;
enum values are a unique finite string
set. `inputRef` starts as `null` and holds a reference into immutable supplied
input rather than copying a string. A v2 `location` starts as `null` and holds
an immutable argument identity and an offset within that argument; it is not
an integer, and cannot index arbitrary input. Tuples have a fixed non-nested
shape.

`set` assigns expressions simultaneously from the pre-transition state. Its
keys must be declared registers and every expression must be statically
assignable to that register. There are no maps, sets, stacks, or growing lists.

Expressions are literals; finite string arrays; `{ "ref": name }`; builtin
calls `{ "call": name, "args": [...] }`; and Boolean `{ "all": [...] }`,
`{ "any": [...] }`, and `{ "not": expression }` nodes. Conditions and fold
predicates must have Boolean type. Known input references include `word`,
`option.value`, `event`, `event.executable`, `event.kind`, `event.gap.reason`,
`fold.item`, declared registers, and cached `fold.<name>` results. v2 also
provides `byte` (the current unsigned byte represented as one U+00xx character)
and `cursor` (a `location` on the current *known* argument). Those two names
are reserved for input references in v2; v1 registers with those names retain
their original meaning. `event` is
available to audit values as the complete immutable policy event.

Terminal templates are arrays of literal strings and finite expressions. A terminal
may list declared `fold` names; those finite folds are evaluated before its condition,
captures, and templates. The `redirects` fold collection supplies input-redirect target
words, so a policy can apply ordinary word predicates to every protected input path.
Terminal
`capture` values are evaluated once from immutable event inputs, final registers,
and cached folds before a template renders; templates may reference those values
as `capture.<name>`.

> **Prototype / design debt:** terminal captures are a deliberately constrained
> diagnostic-template prototype. They have no loops, recursion, includes,
> macros, dynamic property or index lookup, user functions, collection traversal,
> or ambient access. Captures and templates are bounded by the source template
> limit and only evaluate typed, finite expressions, so rendering terminates and
> cannot create unbounded output. This mechanism must be redesigned or explicitly
> expanded before accepting broader template requirements.
Audit objects have source-fixed JSON shape and literal/reference leaves. They
cannot perform calls or scans. A terminal audit has one recursive 4,096-value
budget: every nested object value, array element, and leaf consumes one unit,
so decoded JSON arrays cannot bypass the output-size limit.

## Options and order

An option is:

```json
{
  "names": ["-n", "--namespace"],
  "value": "required",
  "forms": ["separate", "attachedShort", "equalsLong", "cluster"],
  "availableIn": "*",
  "set": { "namespace": { "ref": "option.value" } }
}
```

`value` is `absent`, `required`, or `optional`. Absent options have no value
forms. Value-taking options name one or more of `separate`, `attachedShort`,
`equalsLong`, and `cluster`; short forms require an exact one-byte short name,
and `equalsLong` requires a long name. Option names are globally unique.

The evaluator preserves every Bash argv word, including `--`. It does not apply
an evaluator-wide option terminator rule: a policy may inspect `--` as an
ordinary word, and option declarations may consume it as a separate value. DSL
evaluation only classifies immutable argv; it never changes the command boundary
or the argv passed to the kernel.

`availableIn: "*"` is machine-wide; a non-empty state-name list makes the
option state-local. Compilation inserts applicable options in declaration order
before fragment and state cases in every applicable state. A compiled option
action retains its exact names, value requirement, forms, updates, and static
resume state; the evaluator therefore distinguishes separate, attached-short,
equals-long, and cluster values without reconstructing the declaration. Cluster
parsing sets `clusterByteProgress` and consumes bytes from the current finite
word inside that action; v1 does not create a standalone synthetic cluster
state. In v2, option recognition is confined to word boundaries. Once an
authored `byte` transition enters a word, only authored cases run until that
word is consumed; an option cannot interrupt a partially inspected argument.
While an option cluster is active, `byte` and `cursor` are unknown to authored
cases and authored transitions cannot consume part of that cluster.

## v2 intra-word transitions and spans

The machine cursor is `(argv index, offset)`. `offset = boundary` means no byte
of this argument has been consumed by authored byte transitions; otherwise it
is an integer from 1 through the UTF-8 byte length of the **known** current
argument. The `word` reference remains the complete current argv argument in
either mode. `byte` refers to the byte at offset 0 at a boundary, or at the
current offset in intra-word mode; it is unknown at the end of a word, for an
unknown argument, or at argv EOF. The evaluator does not normalize Unicode,
percent escapes, path separators, or URLs. Policies must explicitly constrain
such syntax before granting permission.

An authored `consume: "byte"` requires a known current argument and an
available byte. It advances the offset by exactly one without advancing argv.
`consume: "word"` at a boundary consumes the whole argument, as in v1; in
intra-word mode it is valid only at the exact end of that argument. This
prevents an ordinary word transition from accidentally accepting an unchecked
suffix. `consume: "restOfWord"` is valid only in intra-word mode: it
deliberately discards the remaining bytes of that argument and advances argv.
An invalid transition is an indeterminate `defer`, never a permit. The
`atEndOfWord()` predicate is true only at the intra-word end of a known
argument. It differs from `atEndOfArguments()`, which is true only at argv EOF.
An empty argument can still be matched and consumed as a whole word, but has
no byte to consume. Terminal actions may occur at any cursor position;
`allow` before word-end means the author has deliberately classified the
entire invocation without checking the remaining bytes.

An abbreviated v2 example showing a span from the start to the end of an
argument (the `start` state consumes the command word first):

```json
{
  "registers": {
    "begin": { "type": "location", "initial": null },
    "piece": { "type": "inputRef", "initial": null }
  },
  "states": {
    "argument": {
      "cases": [{ "when": true, "action": { "consume": "byte", "next": "scan", "set": { "begin": { "ref": "cursor" } } } }],
      "default": { "decision": "defer" }, "end": { "decision": "defer" }
    },
    "scan": {
      "cases": [
        { "when": { "call": "atEndOfWord", "args": [] }, "action": { "consume": "word", "next": "done", "set": { "piece": { "call": "span", "args": [{ "ref": "begin" }, { "ref": "cursor" }] } } } },
        { "when": true, "action": { "consume": "byte", "next": "scan" } }
      ],
      "default": { "decision": "defer" }, "end": { "decision": "defer" }
    },
    "done": { "cases": [], "default": { "decision": "defer" }, "end": { "decision": "allow", "reason": ["argument: ", { "ref": "piece" }] } }
  }
}
```

`cursor` evaluates to a location before the chosen transition consumes input.
Register updates are simultaneous from the pre-transition state. `span(begin,end)`
returns an `inputRef` into the original immutable argument covering the
half-open byte range `[begin,end)`. It is unknown for unset locations,
different arguments, reversed or out-of-bounds endpoints, or an unknown source
word. There is no substring copy stored in a register. The span can be compared
with existing stringish predicates or rendered in a terminal reason/capture.
Materializing a span that cuts through a UTF-8 sequence is unknown rather than
silently inserting replacement characters; such a span cannot prove a match.
Locations from earlier arguments remain valid while that same immutable event
is evaluated. Positions are never writable through arithmetic, string
construction, or dynamic indexing.

## Fragments and folds

Fragments are compile-time case lists:

```json
{
  "uses": ["common"],
  "cases": [{ "when": true, "action": { "decision": "ignore" } }]
}
```

State `fragments` are expanded in listed order before local cases. Fragment
`uses` are expanded before that fragment's cases. References must resolve and
the graph must be acyclic. Validation computes a saturating materialized cost
for every fragment: each use site contributes its complete child cost, including
shared DAG children. It rejects the program before compiler allocation when the
whole compiled expansion exceeds its fixed limit. Fragments are not runtime
calls.

Folds declare exactly one finite engine collection: `argv`, `redirects`,
`assignments`, `provenance`, or `environment`. Operations are `any`, `all`,
`firstRef`, `lastRef`, and `countUpTo` (which has a positive literal `limit`).
Their predicates are Boolean and cannot reference a fold result. A transition
can list declared fold names, which are cached and run at most once per event;
it cannot define a scan. Nested folds and dynamic collections are rejected.

## Closed builtins

All builtins are total and only inspect supplied values. `n`, `m`, `s`, `r`,
`a`, and `p` respectively denote operand, pattern, set, redirect, assignment,
and provenance-route sizes. `stringish` accepts a known string or immutable
input reference and preserves unknown handling for the evaluator.

The table below is the unchanged v1 catalogue (also available in v2).

| Builtin | Signature | Bound | Use |
| --- | --- | --- | --- |
| `equals` | `(stringish, stringish) -> bool` | `O(n)` | exact values |
| `inStringSet` | `(stringish, string-set) -> bool` | `O(n + s)` | finite tables |
| `asciiLower` | `(stringish) -> string` | `O(n)` | ASCII normalize |
| `asciiUpper` | `(stringish) -> string` | `O(n)` | ASCII normalize |
| `equalsAsciiCaseInsensitive` | `(stringish, stringish) -> bool` | `O(n)` | case-insensitive exact match |
| `wordInAsciiCaseInsensitiveSet` | `(stringish, string-set) -> bool` | `O(n + s)` | resource aliases |
| `startsWith` | `(stringish, stringish) -> bool` | `O(n)` | endpoint/path prefix |
| `endsWith` | `(stringish, stringish) -> bool` | `O(n)` | suffix check |
| `includes` | `(stringish, stringish) -> bool` | `O(nm)` | bounded substring |
| `basename` | `(stringish) -> string` | `O(n)` | secret reader paths |
| `pathComponent` | `(stringish, count) -> string` | `O(n)` | lexical paths |
| `pathAfterComponents` | `(stringish, count) -> string` | `O(n)` | separator-preserving path suffixes |
| `splitComponent` | `(stringish, string, count) -> string` | `O(n)` | fixed-delimiter parsing |
| `leadingAsciiDigits` | `(stringish) -> string` | `O(n)` | numeric route identifiers |
| `parseBoundedInt` | `(stringish, count) -> count` | `O(n)` | bounded CLI numbers |
| `boundedIntAtMost` | `(count, count) -> bool` | `O(1)` | number comparison |
| `safeGlob` | `(stringish, string) -> bool` | `O(nm)` | secret path patterns |
| `anySafeGlob` | `(stringish, string-set) -> bool` | `O(nms)` | finite secret path pattern tables |
| `linearRegex` | `(stringish, string) -> bool` | `O(n + m)` | restricted regex |
| `parseUrl` | `(stringish) -> url` | `O(n)` | GitHub URL parsing |
| `urlHost` | `(url) -> string` | `O(1)` | parsed URL hostname |
| `urlPath` | `(url) -> string` | `O(1)` | parsed URL path |
| `urlHostEquals` | `(url, string) -> bool` | `O(n)` | exact host check |
| `parseRepository` | `(stringish) -> repository` | `O(n)` | owner/repository parsing |
| `repositoryEquals` | `(repository, string, string) -> bool` | `O(n)` | PR allowlists |
| `repositoryHasExplicitHost` | `(repository) -> bool` | `O(1)` | explicit repository host proof |
| `repositoryMatches` | `(repository, string, string, string) -> bool` | `O(n)` | finite repository allowlists |
| `repositoryMatchesOrganization` | `(repository, string, string) -> bool` | `O(n)` | finite organization allowlists |
| `normalizeKubernetesResource` | `(stringish) -> string` | `O(n)` | singular/plural resource aliases |
| `normalizeGitHubEndpoint` | `(stringish) -> string` | `O(n)` | GitHub API endpoint paths |
| `environmentLookup` | `(string) -> environment-value` | `O(n)` | env routing |
| `environmentIsPresent` | `(environment-value) -> bool` | `O(1)` | env presence |
| `environmentIsKnown` | `(environment-value) -> bool` | `O(1)` | env proof |
| `environmentIsUnknown` | `(environment-value) -> bool` | `O(1)` | unresolved env proof |
| `environmentValueEquals` | `(environment-value, string) -> bool` | `O(n)` | exact env proof value; unknown remains unknown |
| `environmentIsExported` | `(string) -> bool` | `O(1)` | exported proof variable |
| `missingEnvironmentMayBePresent` | `() -> bool` | `O(1)` | absent versus unknown environment |
| `redirectHasInputPath` | `(stringish) -> bool` | `O(r + n)` | secret redirects |
| `hasAssignment` | `(string) -> bool` | `O(a)` | prefix assignments |
| `hasAnyAssignment` | `() -> bool` | `O(1)` | any prefix assignment |
| `assignmentsAreSubset` | `(string-set) -> bool` | `O(as)` | finite assignment allowlist |
| `hasRedirect` | `() -> bool` | `O(1)` | redirection boundary |
| `atEndOfArguments` | `() -> bool` | `O(1)` | EOF-only terminal guard |
| `isDirectExecutable` | `(string) -> bool` | `O(n)` | exact unqualified executable |
| `hasInheritedExecutableFunction` | `(string) -> bool` | `O(n)` | imported function shadowing |
| `executionTargetIs` | `(string) -> bool` | `O(1)` | resolved target: `builtin`, `shell-function`, `external-path`, or `unresolved` |
| `environmentAnyUnsafe` | `(string-set) -> bool` | `O(ns)` | finite unsafe environment routes |
| `longOptionPrefixesAny` | `(stringish, string-set) -> bool` | `O(ns)` | audited long-option prefix table |
| `hasProvenanceRoute` | `(string) -> bool` | `O(p)` | shell-wrapper routes |
| `isInPipeline` | `() -> bool` | `O(1)` | pipeline context |
| `processEffectIs` | `(string) -> bool` | `O(1)` | process effects |
| `inputIsBindingResolved` | `(stringish) -> bool` | `O(1)` | binding-derived input provenance |
| `inputBlockedDomain` | `(stringish) -> string` | `O(1)` | unresolved-input blocked-domain metadata |
| `domainToken` | `(stringish, string) -> bool` | `O(nm)` | ASCII domain mention with hostname boundaries |

Only v2 adds the following total builtins:

| Builtin | Signature | Bound | Use |
| --- | --- | --- | --- |
| `atEndOfWord` | `() -> bool` | `O(1)` | exact intra-word end |
| `span` | `(location, location) -> input-ref` | `O(1)` | immutable half-open slice reference |

Policy events retain `BASH_FUNC_name%%` as an ordinary, exact environment
binding. The walker also imports valid exported Bash definitions into shell
state and analyzes calls to them like locally defined functions. An unrecognized
or malformed imported definition emits a request-wide execution gap: a policy
cannot automatically allow that Bash source, but a concrete denial still wins.
If shell code redefines or exports a function, its exact Bash-generated
environment serialization is modeled as unknown; the known definition remains
available for analysis when a subsequent Bash child inherits that export.

`executionTargetIs` tests the immediate command lookup, independently of
`hasProvenanceRoute`. For example, an ordinary `helm` invocation can resolve to
a shell function, while the child of `strace helm` is looked up as an external
executable even if `BASH_FUNC_helm%%` is present. `command helm` skips shell
functions but can resolve a builtin; `builtin helm` accepts only builtins.
`unresolved` targets cannot contribute to automatic authorization.

`linearRegex` has a handwritten restricted grammar: an optional leading `^`,
literal bytes, `.`, non-empty terminated character classes, only escapes of
`\\.^$[]-`, and an optional trailing `$`. It rejects malformed/empty classes,
truncated or unknown escapes, grouping, alternation, repetition, lookaround,
and backreferences. `safeGlob` has only literal, `?`, and `*` forms. URL and
repository parsing are strict lexical parsing, never lookup. No locale,
filesystem, process, network, clock, randomness, module, or callback access is
available.

## Validation limits and progress proof

Both versions limit source JSON to 256 KiB; states to 512; registers to 64; folds to 32;
options to 64; selectors to 256; option names to 16; fragments to 64; cases
per state to 128; and source/compiled transitions, expanded cases, and
templates to 4,096. Expression nodes are limited to 32,768, literal bytes to
16,384, regex bytes to 8,192, and audit depth to 16. Validation is linear in
the source structure plus explicit state-local option availability and fragment
edges. It indexes option availability once and uses saturating DAG accounting;
it does not scan every option for every state.

Enum domains are canonicalized once from their ordered finite value table.
An enum assignment compares canonical domain identities rather than rescanning
the table, so repeated equal-domain references remain linear in policy size.
Validation metrics separately report enum-domain checks and the identity
comparisons they perform. Equality receives only opaque canonical identity
tokens, so it cannot inspect a domain table. Test-only observers count both
identity comparisons and every entry read from validator-internal enum tables;
the scaling property proves that table reads remain confined to one
canonicalization pass rather than growing with assignments.

For v1, every authored nonterminal consumes one word; for v2 it consumes a
word, one byte, or the remainder of a word. Option-cluster microsteps consume
one byte. Let `A` be the sum of UTF-8 argument byte lengths plus one boundary
unit per argument. Assign every cursor the number of unread bytes plus unread
boundary units: at an argument boundary all its bytes and its boundary are
unread, and in intra-word mode only the bytes after the offset and that
boundary are unread. Every valid `byte` transition decreases this measure by
one. A `word` or `restOfWord` transition removes the current boundary and any
unread bytes; an option consumes at least a byte or a word. No transition may
rewind or switch to another argument without consuming the current boundary.
Therefore every nonterminal strictly decreases a finite natural number, even
on an empty argument. At EOF or unmatched input evaluation terminates. Invalid
transitions defer. Combined with acyclic fragments, fixed registers, single-run
non-nested folds, static transition targets, and total builtins, every valid
policy terminates without runtime fuel.

Each location is a pair of bounded coordinates into immutable input. `span`
creates a reference, not a string or a collection. With `P` compiled policy
size and `B` total immutable input/context size, working storage stays
`O(P+B)`; rendering a bounded template can materialize `O(PB)` output.
There are at most `O(B)` consuming steps; at each step `O(P)` cases may each
inspect an `O(B)` value, yielding the existing conservative `O(PB²)` time
bound. Byte and cursor reads are constant-time within a cached encoding of the
current word. Location registers cannot implement a stack or accumulate text.
The validator and compiler count byte/rest transitions under the same fixed
source and expanded transition limits as word transitions.
`atEndOfArguments()` is an explicit EOF predicate for terminal actions. Use it when an accepted grammar must reject unrecognized option words before allowing the completed command.

The 512-state cap accommodates the checked-in, pinned GitHub CLI command trie
while preserving a fixed resource bound.
