# `tea repos list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only repository enumeration. It protects repository creation, templating, forking, migration, deletion, editing, and every non-list repository route.


## Accepted grammar

The complete route is `tea {repos|repo} {list|ls}` with zero operands. Before or after the leaf, valueless `--watched`/`-w` and `--starred`/`-s` may each repeat. At the same parent-or-leaf placement, `--owner`/`-O`, `--fields`/`-f`, `--type`/`-T`, `--page`/`-p`, `--login`/`-l`, and `--output`/`-o` may each repeat and require one value. `--limit`, `--lm`, and named alias `-lm` are one-value aliases with that placement and cardinality. Long aliases permit separate or `=` values, ordinary short aliases permit only separate values, and named `-lm` permits only `-lm VALUE`. Valueless flags accept no values. No attached short values or short clusters are accepted; `-lm` is explicitly a named alias, not a cluster.

## Outcomes

Allow only this grammar at EOF under the trusted execution assumption. Defer operands, any other repository route, unknown or misplaced option, a value on a valueless flag, malformed required value, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy has no deny outcome.

## Scope limits and non-goals

It does not mutate repositories, validate filter values, inspect response data, or establish server authorization. The threat model is normal use of Tea `bcd62a1`, not adversarial policy evasion.

Sources: [`cmd/repos.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos.go), [`cmd/repos/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
