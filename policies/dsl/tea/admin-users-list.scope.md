# `tea admin users list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits listing administrative users only. It protects user creation, modification, deletion, detail-route operands, and other admin actions.


## Accepted grammar

The complete route is `tea {admin|a} {users|u} {list|ls}` with zero positional operands. After `users`/`u` or after `list`/`ls`, each of these can occur zero or more times and requires one value: `--fields`/`-f`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o`. `--limit`, `--lm`, and named alias `-lm` are separate spellings of the one-value limit option with the same placement. Long options allow `--long VALUE` or `--long=VALUE`; ordinary short aliases allow only `-x VALUE`; the named alias allows only `-lm VALUE`. No attached short values or short clusters are accepted.

## Outcomes

Allow only that route at EOF under the trusted execution assumption. Defer any operand, different route, mutation token, unknown or misplaced option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This scope never denies.

## Scope limits and non-goals

The contract does not authorize user mutations, validate option values or server permissions, or interpret response data. It covers normal use of the pinned CLI, not adversarial policy evasion.

Source: [`cmd/admin/users/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/admin/users/list.go).
