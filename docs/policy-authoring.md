# Policy authoring

`safety-core` has two policy source forms. Global configuration may reference
trusted code (`.policy.mjs`) and declarative DCRM (`.policy.json`) sources.
Project configuration may reference only declarative DCRM sources. Code policy
is executable trusted code: it must export exactly one frozen default object,
cannot use relative runtime imports, and is appropriate only when the policy
author and deployment path are trusted. Prefer DCRM for reviewable policy data.

## Configuration schemas

The global configuration is a closed object:

```json
{
  "version": 1,
  "policies": ["/absolute/global.policy.json", "/absolute/guard.policy.mjs"],
  "projectPolicies": { "mode": "allowlisted", "allowedRoots": ["/work/reviewed-project"] },
  "bashAnalysis": {
    "maxFunctionDepth": 128,
    "maxNestedScriptDepth": 64,
    "maxSteps": 7500,
    "maxWorkItems": 10000
  }
}
```

`projectPolicies.mode` is exactly `disabled`, `allowlisted`, or `all`.
`allowlisted` needs absolute roots. The nearest `.safety-core/config.json` at
or above the working directory is selected only when that global mode permits
it. The project document is also closed and has exactly `version: 1` plus its
`policies` array; every entry must end in `.policy.json`. Project permission
policies add coverage, while a guard denial from any selected source wins.

At startup, paths are canonicalized and the raw configuration and policy bytes
are SHA-256 hashed. Treat that identity as part of the review: a symlink target,
changed source, or changed selected project is a different policy. `validate`
prints the selected identities. Claude verifies the same snapshot for each
isolated hook; OpenCode and Pi retain the startup object, so restart those
harnesses after editing sources.

## DCRM documents

The full grammar and builtin table are in [policy-dsl.md](./policy-dsl.md).
DCRM is a JSON-only deterministic consuming register machine. Every object has
an exact schema, duplicate JSON keys are rejected, and `language` is exactly
`safety-core/bash-policy-v1`. A source names a `guard` or `permission` layer,
exact selectors, fixed registers/options/folds/fragments, a start state, and
closed state definitions. A guard can deny, defer, or ignore; it cannot allow.
`allow` and `deny` require a finite reason template. `ignore` means the source
does not own that event; `defer` leaves it to native harness permission; deny
is final. Automatic allow needs complete analysis and permission coverage for
every reachable modeled event.

Selectors are exact. Invocation selectors match all invocation events; an
executable selector can match only `basename`, `selected-path`,
`canonical-target`, or `chain-contains`. Use a path projection when the policy
depends on a deployed binary rather than a command spelling.

Options are declared, not guessed. State each exact spelling, whether it takes
an absent, optional, or required value, and the accepted separate,
attached-short, equals-long, and cluster forms. The compiler checks applicable
options before normal state cases, so supported flags can appear in their valid
positions without treating unknown flags as harmless. An accepted grammar
should use `atEndOfArguments()` before allowing it; unconsumed words then defer
instead of accidentally matching a prefix.

Diagnostics are finite source data. Reason/suggestion templates contain only
literals and typed finite expressions; audit values have a closed, bounded
shape. Captures are a deliberately narrow diagnostic-template prototype, not a
general templating language: no loops, recursion, includes, macros, dynamic
lookup, user functions, ambient access, or collection traversal. They must be
redesigned or explicitly expanded before accepting broader template features.

## Why DCRM terminates

Registers have fixed finite domains, fragments are acyclic compile-time
expansions, folds scan only one fixed engine collection once, builtin functions
are total, and transition targets are static. Each authored nonterminal
consumes one argv word; each compiler-created option-cluster transition consumes
one byte. The decreasing measure is remaining argv boundaries plus active
cluster bytes. Source, state, expression, expansion, and output budgets are
validated before compilation, so valid policies terminate without runtime fuel.
The Bash analyzer still has explicit finite analysis limits; exhaustion or
incomplete values must defer, never authorize.
