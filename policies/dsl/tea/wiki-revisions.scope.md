# `tea wiki revisions` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only revision-history inspection for one Wiki page. It protects Wiki mutations and all unrelated Wiki routes.


## Accepted grammar

The complete route is `tea wiki {revisions|history} PAGE`; `PAGE` is exactly one required non-option operand. Before the child route, after it, or after `PAGE`, each of `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, `--fields`/`-f`, and `--page`/`-p` may repeat and takes one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with the same placement. Long aliases permit separate or `=` values, ordinary short aliases permit only separate values, and named `-lm` permits only `-lm VALUE`. All attached short values and other short clusters defer.

## Outcomes

Allow only this grammar at EOF under the trusted execution assumption. Defer missing or surplus pages, another route, unknown or misplaced option, malformed value, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Scope limits and non-goals

It does not authorize Wiki writes, validate page names or filter values, inspect server responses, or establish remote authorization. The threat model is normal pinned-Tea use, not adversarial bypass.

Source: [`cmd/wiki/read.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/wiki/read.go).
