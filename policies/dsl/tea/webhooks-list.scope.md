# `tea webhooks list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only webhook listing. It protects webhook creation, updates, deletion, detail inspection routes, and delivery configuration.


## Accepted grammar

The complete route is `tea {webhooks|webhook|hooks|hook} {list|ls}` with zero operands. Before or after `list`/`ls`, inherited `--org VALUE` and valueless `--global` may each repeat. At those same positions, each of `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, and `--page`/`-p` may repeat and requires one value. `--limit`, `--lm`, and named `-lm` are one-value aliases with that same parent-or-leaf placement. Long aliases accept separate or `=` values, ordinary short aliases accept only separate values, and named `-lm` accepts only `-lm VALUE`. `--global` takes no value. No attached short value or short cluster is accepted; `-lm` is the sole named multi-character short alias.

## Outcomes

Allow only this grammar at EOF under the trusted execution assumption. Defer any operand, other route, unknown option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Scope limits and non-goals

It does not authorize webhook configuration changes, validate target selection or values, or establish remote authorization. It covers normal Tea `bcd62a1` invocation only.

Source: [`cmd/webhooks/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/webhooks/list.go).
