# `tea wiki view` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only retrieval of one Wiki page. It protects page mutations and routes that list pages or inspect revision history.


## Accepted grammar

The complete route is `tea wiki view PAGE`; `PAGE` is exactly one required non-option operand. Before `view`, after `view`, or after `PAGE`, each of `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, `--fields`/`-f`, and `--page`/`-p` may repeat and takes one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same placement. Long aliases permit separate or `=` values, ordinary shorts permit only separate values, and named `-lm` permits only `-lm VALUE`. Attached short values and short clusters are forbidden, except for `-lm` as the named alias.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer missing or surplus pages, another route, unknown or misplaced option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. No deny result exists.

## Scope limits and non-goals

The scope does not create, edit, delete, or validate the page; it does not validate values, server privileges, or returned content. It assumes ordinary use of Tea `bcd62a1`.

Source: [`cmd/wiki/read.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/wiki/read.go).
