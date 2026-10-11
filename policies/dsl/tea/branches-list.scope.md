# `tea branches list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only branch enumeration. It protects branch protection changes, unprotection, renaming, and other repository mutations.


## Accepted grammar

The complete route is `tea {branches|branch|b} {list|ls}` with zero operands. Before or after `list`/`ls`, valueless `--comments` may repeat. At those same positions, `--fields`/`-f`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o` may each repeat and require one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same parent-or-leaf placement. Long aliases use separate or `=` values, ordinary short aliases use separate values, and named `-lm` uses only `-lm VALUE`. `--comments` takes no value. No attached short value or short cluster is accepted; `-lm` is allowed only as the named alias.

## Outcomes

Allow only this grammar at EOF under the trusted execution assumption. Defer operands, another route, a value on `--comments`, unknown or misplaced option, malformed value, branch mutation route, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Scope limits and non-goals

It does not protect or rename branches, validate selectors or output, inspect results, or grant remote authorization. It is limited to normal Tea `bcd62a1` behavior.

Sources: [`cmd/branches.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/branches.go) and [`cmd/branches/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/branches/list.go).
