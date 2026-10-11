# `tea actions secrets list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only enumeration of Actions secret metadata. It protects secret creation, replacement, deletion, and secret-value mutation.


## Accepted grammar

The route is `tea {actions|action} {secrets|secret} {list|ls}` with zero operands. Before the intermediate namespace or between that namespace and the leaf, inherited Actions flags allow `--repo VALUE` or `--repo=VALUE`, `--login VALUE` or `--login=VALUE`, and `--output VALUE`, `--output=VALUE`, or `-o VALUE`; each may repeat. After the leaf, leaf generic flags additionally allow `-r VALUE`, `--remote VALUE`, `--remote=VALUE`, `-R VALUE`, and `-l VALUE`. After the leaf only, `--page`/`-p` each takes one value, and `--limit`, `--lm`, and named `-lm` are one-value aliases. Attached short values and all short clusters defer; `-lm` is accepted only as the named separate-value alias.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer operands, root options, leaf-only options before the leaf, unknown option, malformed value, secret mutation route, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This scope never denies.

## Scope limits and non-goals

It does not expose secret values, modify secrets, validate values or remote permissions, or inspect response content. It covers normal Tea `bcd62a1` use rather than adversarial bypass.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/secrets.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/secrets.go), and [`cmd/actions/secrets/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/secrets/list.go).
