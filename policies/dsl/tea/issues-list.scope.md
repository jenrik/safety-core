# `tea issues list` Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

`issues-list.policy.json` permits list-only issue reads while protecting issue
state. It passes filter and output values to Tea unchanged; Tea validates their
domains.

## Exact scope and aliases

The exact route is `tea {issues|issue|i} {list|ls} [FLAGS ...]`. Upstream
defines the route in [`cmd/issues/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/issues/list.go), its filters in [`cmd/flags/issue_pr.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/issue_pr.go), and pagination/shared routing flags in [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).

## Required operands

None. The route accepts only options after the top-level `{issues|issue|i}`
token (before or after the `{list|ls}` leaf), and no bare operands.

## Exact option grammar

Only supported separate short and long forms (including `--long=value`) are accepted after the command route; unsupported short attachment and clustering defer.

Shared routing/output options are `--login|-l`, `--repo|-r`, `--remote|-R`,
and `--output|-o`.

Route-local filter/output options are:

- `--comments[=BOOL]`
- `--fields|-f VALUE`
- `--state VALUE`
- `--kind|-K VALUE`
- `--keyword|-k VALUE`
- `--labels|-L VALUE`
- `--milestones|-m VALUE`
- `--author|-A VALUE`
- `--assignee|-a VALUE`
- `--mentions|-M VALUE`
- `--owner|--org VALUE`
- `--from|-F VALUE`
- `--until|-u VALUE`
- `--page|-p VALUE`
- `--limit|--lm VALUE`

`--fields`, `--labels`, and `--milestones` accept Tea's comma-separated value
syntax. Filters may repeat and may be interleaved in any order; the policy
only verifies complete option syntax and leaves Tea's value/domain validation
to Tea.

## Exclusions and threat model

Missing option values, unknown options, extra operands, and sibling write routes
defer immediately. Assignments, redirections, and inherited `tea` shell
functions also defer. Other executable spellings are outside the
non-adversarial threat model.

## Assumptions and non-goals

Tea validates filtering, pagination, field selection, and output values. This
policy does not validate query results or widen the list route to issue mutation.

## Permit/defer/deny behavior

It permits a complete direct route with no assignments, redirects, or inherited function. Every other form defers; it never denies.
