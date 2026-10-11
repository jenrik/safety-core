# `tea milestones list` Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

`milestones-list.policy.json` permits read-only milestone listing while
protecting milestone state from creation, editing, closing, reopening, or
deletion. It passes all accepted filter, pagination, routing, and output values
to Tea unchanged; Tea validates their meanings.

## Exact route and operands

The complete route is `tea {milestones|milestone|ms} {list|ls}`. It has no
positional operands: every token after `tea` must be a permitted route alias or
a permitted option with its required value. Upstream defines the list route in
[`cmd/milestones/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/milestones/list.go).

## Exact option grammar

Each option below takes exactly one value, may occur zero or more times, and may
appear in any order after `{milestones|milestone|ms}` or after `{list|ls}`. The
options may therefore be interleaved around the leaf, but none may precede the
top-level milestone alias.

- `--fields` or `-f`
- `--state`
- `--page` or `-p`
- `--limit`, `--lm`, or named alias `-lm`
- `--login` or `-l`
- `--repo` or `-r`
- `--remote` or `-R`
- `--output` or `-o`

Long aliases accept `--long VALUE` or `--long=VALUE`; ordinary short aliases
accept only `-x VALUE`. `-lm` is a named limit alias, not a short cluster, and
accepts only `-lm VALUE`. There are no valueless options or positional selector
forms in this contract.

## Threat model and non-goals

This policy covers natural invocations of the trusted Tea-compatible CLI, not
an adversary substituting another executable or deliberately bypassing the
selected `tea` command. It does not validate repository selection, remote
identity, authentication, option value domains, the remote response, or the
effects of reading remote data. It also does not authorize any sibling
milestone route or mutation operation.

## Outcomes

Allow requires the complete grammar at end of arguments and the execution
boundary above. Missing option values, bare operands, extra route tokens,
unknown or misplaced options, unsupported option forms, mutation or other
sibling routes, assignments, redirects, inherited functions, and
execution-boundary mismatches defer. Binary identity remains unverified and
outside assurance. The policy has no deny outcome.
