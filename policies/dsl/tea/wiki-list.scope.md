# `tea wiki list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits listing Wiki pages only. It protects page mutations, page-detail routes, revision routes, and all non-list wiki commands.


## Accepted grammar

The complete route is `tea wiki {list|ls}` with zero operands. Before or after the leaf, each of `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, `--fields`/`-f`, and `--page`/`-p` may repeat and requires exactly one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same placement. Long aliases accept `--long VALUE` and `--long=VALUE`; ordinary short aliases accept `-x VALUE`; named `-lm` accepts only `-lm VALUE`. Attached short forms and every other short cluster are forbidden.

## Outcomes

Allow only this grammar at EOF under the execution boundary. Defer operands, another route, unknown or misplaced options, malformed values, direct Tea assignments or redirects, inherited functions, path-qualified Tea, non-external-path targets, and execution-boundary mismatches. This policy has no deny branch.

## Scope limits and non-goals

It does not grant wiki write access, validate selector values or response data, or establish server authorization. It covers ordinary pinned-Tea use only.

Source: [`cmd/wiki/read.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/wiki/read.go).
