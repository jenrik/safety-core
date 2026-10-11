# `tea times list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only time-tracking inspection. It protects time entry addition, deletion, reset, and all other mutating time routes.


## Accepted grammar

The route is `tea {times|time|t} {list|ls} [USERNAME_OR_ISSUE]`, where the optional selector is exactly one non-option token. Before the leaf, after it, or after the selector, each may repeat: one-value `--from`/`-f`, `--until`/`-u`, `--fields`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o`; one-value `--limit`, `--lm`, and named `-lm`; and valueless `--total`/`-t` and `--mine`/`-m`. Long aliases use separate or `=` values, ordinary short aliases use separate values, and named `-lm` uses only `-lm VALUE`. `--total` and `--mine` take no value. Attached short values and short clusters are forbidden; `-lm` is a named alias, not a cluster.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer a surplus selector, unknown or misplaced option, valueless flag with a value, malformed required value, time mutation route, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy has no deny outcome.

## Scope limits and non-goals

It does not create, remove, or reset time entries; validate selector or filter values; inspect results; or establish remote authorization. It addresses normal pinned-Tea use only.

Sources: [`cmd/times.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/times.go) and [`cmd/times/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/times/list.go).
