# `tea notifications ls` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only notification listing. It protects notification read-state and pin-state mutations and every non-list notification route.


## Accepted grammar

The complete route is `tea {notifications|notification|n} {ls|list}` and has zero operands. After the parent or leaf, each option may repeat: `--fields`/`-f`, `--types`/`-t`, `--states`/`-s`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o` take one value; `--limit`, `--lm`, and named `-lm` also take one value; `--mine`/`-m` is valueless. Long aliases use separate or `=` values, ordinary shorts use separate values, and the named alias uses only `-lm VALUE`. No attached short value or short cluster is accepted; `-lm` is allowed only as the named limit alias.

## Outcomes

Allow only this grammar at EOF under the trusted execution assumption. Defer operands, another route, unknown or misplaced option, value supplied to `--mine`/`-m`, malformed required value, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. There is no deny branch.

## Scope limits and non-goals

The scope does not change notification state, validate filters or response content, or grant server-side access. It addresses normal Tea `bcd62a1` usage only.

Source: [`cmd/notifications/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/notifications/list.go).
