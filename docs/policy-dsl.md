# DCRM policy language v1

`safety-core/bash-policy-v1` is a JSON-only deterministic consuming register
machine (DCRM). It classifies one immutable policy event. It cannot call host
code, mutate the event, access files/processes/network/clock/modules, allocate
dynamic collections, retain state across events, recurse, rewind input, or
compute a jump target.

The loader for JSON sources is introduced separately. This document specifies
the source document accepted by `parsePolicyDocument`,
`validatePolicyDocument`, and `compilePolicyDocument`.

## Document

Every object is closed: an unknown member is an error. The language value is
exactly `safety-core/bash-policy-v1`; compatible prefixes and later versions
are not accepted. JSON text is scanned for duplicate object keys before it is
decoded, so a later declaration cannot silently replace an earlier one.

```text
Policy := {
  language, layer, select, registers?, folds?, options?, fragments?, start, states
}
layer := "guard" | "permission"
State := { fragments?, cases, default, end }
Case := { when, action }
Transition := { consume: "word", next, set?, fold? }
Terminal := { decision, reason?, suggestion?, audit? }
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
fixed `tuple` are the complete v1 domains. `count` has a positive literal
`max` and an in-range literal `initial`; enum values are a unique finite string
set. `inputRef` starts as `null` and holds a reference into immutable supplied
input rather than copying a string. Tuples have a fixed non-nested shape.

`set` assigns expressions simultaneously from the pre-transition state. Its
keys must be declared registers and every expression must be statically
assignable to that register. There are no maps, sets, stacks, or growing lists.

Expressions are literals; finite string arrays; `{ "ref": name }`; builtin
calls `{ "call": name, "args": [...] }`; and Boolean `{ "all": [...] }`,
`{ "any": [...] }`, and `{ "not": expression }` nodes. Conditions and fold
predicates must have Boolean type. Known input references include `word`,
`option.value`, `event`, `event.executable`, `event.kind`, `event.gap.reason`,
`fold.item`, declared registers, and cached `fold.<name>` results. `event` is
available to audit values as the complete immutable policy event.

Terminal templates are arrays of literal strings and finite expressions. Terminal
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

`availableIn: "*"` is machine-wide; a non-empty state-name list makes the
option state-local. Compilation inserts applicable options in declaration order
before fragment and state cases in every applicable state. A compiled option
action retains its exact names, value requirement, forms, updates, and static
resume state; the evaluator therefore distinguishes separate, attached-short,
equals-long, and cluster values without reconstructing the declaration. Cluster
parsing sets `clusterByteProgress` and consumes bytes from the current finite
word inside that action; v1 does not create a standalone synthetic cluster
state.

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

## Closed v1 builtins

All builtins are total and only inspect supplied values. `n`, `m`, `s`, `r`,
`a`, and `p` respectively denote operand, pattern, set, redirect, assignment,
and provenance-route sizes. `stringish` accepts a known string or immutable
input reference and preserves unknown handling for the evaluator.

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
| `linearRegex` | `(stringish, string) -> bool` | `O(n + m)` | restricted regex |
| `parseUrl` | `(stringish) -> url` | `O(n)` | GitHub URL parsing |
| `urlHost` | `(url) -> string` | `O(1)` | parsed URL hostname |
| `urlPath` | `(url) -> string` | `O(1)` | parsed URL path |
| `urlHostEquals` | `(url, string) -> bool` | `O(n)` | exact host check |
| `parseRepository` | `(stringish) -> repository` | `O(n)` | owner/repository parsing |
| `repositoryEquals` | `(repository, string, string) -> bool` | `O(n)` | PR allowlists |
| `normalizeKubernetesResource` | `(stringish) -> string` | `O(n)` | singular/plural resource aliases |
| `normalizeGitHubEndpoint` | `(stringish) -> string` | `O(n)` | GitHub API endpoint paths |
| `environmentLookup` | `(string) -> environment-value` | `O(n)` | env routing |
| `environmentIsPresent` | `(environment-value) -> bool` | `O(1)` | env presence |
| `environmentIsKnown` | `(environment-value) -> bool` | `O(1)` | env proof |
| `environmentIsUnknown` | `(environment-value) -> bool` | `O(1)` | unresolved env proof |
| `environmentValueEquals` | `(environment-value, string) -> bool` | `O(n)` | exact env proof value |
| `environmentIsExported` | `(string) -> bool` | `O(1)` | exported proof variable |
| `missingEnvironmentMayBePresent` | `() -> bool` | `O(1)` | absent versus unknown environment |
| `redirectHasInputPath` | `(stringish) -> bool` | `O(r + n)` | secret redirects |
| `hasAssignment` | `(string) -> bool` | `O(a)` | prefix assignments |
| `hasProvenanceRoute` | `(string) -> bool` | `O(p)` | shell-wrapper routes |
| `isInPipeline` | `() -> bool` | `O(1)` | pipeline context |
| `processEffectIs` | `(string) -> bool` | `O(1)` | process effects |
| `inputIsBindingResolved` | `(stringish) -> bool` | `O(1)` | binding-derived input provenance |
| `inputBlockedDomain` | `(stringish) -> string` | `O(1)` | unresolved-input blocked-domain metadata |

`linearRegex` has a handwritten restricted grammar: an optional leading `^`,
literal bytes, `.`, non-empty terminated character classes, only escapes of
`\\.^$[]-`, and an optional trailing `$`. It rejects malformed/empty classes,
truncated or unknown escapes, grouping, alternation, repetition, lookaround,
and backreferences. `safeGlob` has only literal, `?`, and `*` forms. URL and
repository parsing are strict lexical parsing, never lookup. No locale,
filesystem, process, network, clock, randomness, module, or callback access is
available.

## Validation limits and progress proof

v1 limits source JSON to 256 KiB; states to 128; registers to 64; folds to 32;
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

Every authored nonterminal has `consume: "word"`, which consumes one forward
argv boundary. Every compiler-created cluster transition consumes one forward
byte. Thus every nonterminal transition strictly decreases the finite measure
of remaining argv token boundaries plus bytes in an active cluster. EOF and
unmatched input always terminate. Combined with acyclic compile-time fragments,
fixed registers, single-run non-nested folds, static transition targets, and
total builtins, a valid program terminates without runtime fuel.
