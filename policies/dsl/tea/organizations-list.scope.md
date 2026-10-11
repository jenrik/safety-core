# `tea organizations list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only organization enumeration. It protects organization creation, deletion, and all non-list organization routes.


## Accepted grammar

The complete route is `tea {organizations|organization|org} {list|ls}` with zero operands. Before or after the leaf, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, and `--page`/`-p` may each repeat and require one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same placement and cardinality. Long aliases use `--long VALUE` or `--long=VALUE`; ordinary short aliases use `-x VALUE`; named `-lm` uses only `-lm VALUE`. Attached short values and all short clusters are forbidden except for `-lm` as the named limit alias.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer operands, another route, unknown or misplaced option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. No deny branch exists.

## Scope limits and non-goals

This contract does not change organizations, validate values or remote permissions, or inspect returned content. It applies to normal Tea `bcd62a1` use only.

Sources: [`cmd/organizations.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/organizations.go), [`cmd/organizations/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/organizations/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
