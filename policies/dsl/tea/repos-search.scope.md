# `tea repos search` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only repository search. It protects repository creation, migration, forking, editing, deletion, and every other mutating repository route.


## Accepted grammar

The route is `tea {repos|repo} {search|s} [TERM ...]`; zero or more non-option terms are accepted after the leaf and may be interleaved with leaf options. Valueless `--watched`/`-w` and `--starred`/`-s` may repeat before `search`/`s`, after it, or after terms. At those same positions, `--owner`/`-O`, `--fields`/`-f`, `--type`/`-T`, `--page`/`-p`, `--login`/`-l`, and `--output`/`-o` may repeat and require one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same placement. After the leaf or after terms only, `--private` and `--archived` require one value, while `--topic`/`-t` is valueless. Long aliases allow separate or `=` values; ordinary short aliases allow separate values; named `-lm` allows only `-lm VALUE`. No attached short value or short cluster is accepted, except named `-lm` as an explicit alias.

## Outcomes

Allow only that grammar at EOF under the trusted execution assumption. Defer unknown option, a value on a valueless flag, malformed value form, repository mutation route, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Scope limits and non-goals

It does not modify repositories, validate search terms or filters, inspect result content, or establish server authorization. The threat model is normal use of Tea `bcd62a1`, not adversarial evasion.

Sources: [`cmd/repos.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos.go), [`cmd/repos/search.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos/search.go), and [`cmd/repos/flags.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos/flags.go).
