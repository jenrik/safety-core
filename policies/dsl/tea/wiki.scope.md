# `tea wiki` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits the read-only Wiki parent/help route. It protects wiki page creation, editing, deletion, and all child behavior not recognized by the dedicated read-only leaf scopes.


## Accepted grammar

The parent route is exactly `tea wiki` and has zero operands. It has no route aliases. Before EOF on that parent route, each of `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, `--fields`/`-f`, and `--page`/`-p` may repeat and requires one value. `--limit`, `--lm`, and named alias `-lm` are one-value aliases with the same parent-only placement. Long aliases allow separate or `=` values, ordinary short aliases allow only separate values, and named `-lm` allows only `-lm VALUE`. No attached short value or short cluster is accepted.

`list`/`ls`, `view`, and `revisions`/`history` are child routes delegated to their respective leaf scopes; this parent scope does not itself allow a child invocation.

## Outcomes

Allow only the parent grammar at EOF under the execution boundary. Defer all children for leaf handling, page mutation children, operands, unknown or misplaced options, malformed values, direct Tea assignments or redirects, inherited functions, path-qualified Tea, non-external-path targets, and execution-boundary mismatches. This policy never returns deny.

## Scope limits and non-goals

This contract neither grants page-write access nor validates repository selection, page names, values, server permissions, or responses. It models normal Tea `bcd62a1` usage, not adversarial bypass attempts.

Sources: [`cmd/wiki.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/wiki.go) and [`cmd/wiki/read.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/wiki/read.go).
