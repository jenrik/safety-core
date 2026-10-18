# Tea shared scope

Every co-located Tea policy scope incorporates this document through its
[Tea shared scope](scope.md) reference. Its route-specific sections define the
intent and protected asset, exact argv grammar, and route-specific outcomes.

## Compatibility and executable identity

Tea `bcd62a1` compatibility is an unverified operator assumption. These
policies do not verify the selected binary's identity, provenance, version, or
behavior. A same-named incompatible or replaced `tea` is outside this
assurance and may syntactically match and be allowed.

A matching grammar applies to an unqualified bare `tea` invocation classified
as `external-path`. The selected PATH identity may be known, incomplete, or not
found; a resolved path or verified identity is neither required nor checked.
Path-qualified spellings and inherited `tea` shell functions are not this
external Tea invocation and remain subject to their own modeled decision.

## Parser assumptions

At Tea `bcd62a1`, root-level options before the top-level command are
unsupported and defer unless a route-specific grammar says otherwise. After a
command route, the shared parser convention accepts only `--long VALUE`,
`--long=VALUE`, and `-x VALUE`. Short clusters and attached short values defer.
The DSL cannot express `-x=VALUE` without also admitting unsupported
`-xVALUE`, so both defer.

## Transparent wrappers

A transparent execution wrapper, including a permitted `env` command, does not
by itself defer a valid Tea child. The wrapper envelope is assessed
independently, and its child Tea invocation retains its argv and provenance for
the Tea grammar and audit. The complete composition is allowable only when the
wrapper and the Tea child are each allowed; an unsupported wrapper form,
assignment, redirect, function, or other modeled effect receives its own
decision and cannot inherit the child's allow.

## Threat model and shared outcomes

The threat model is ordinary, non-adversarial use of a Tea-compatible binary.
These scopes do not establish server authorization, validate Tea option values
or remote responses, inspect output, or govern direct APIs, alternate clients,
or deliberate policy-evasion transports.

Tea permission policies return `allow` only for their complete documented
grammar and otherwise return `defer`; they have no `deny` rules. A separate
guard policy may deny an invocation, and that deny dominates a Tea allow.

The `open` and `logins helper get` routes have no permitted form. Their sources
are guard policies that recognize the routes and return `defer`; both routes
remain prompt-gated because no Tea permission policy covers them.
