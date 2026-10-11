# `tea admin users` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only enumeration or detail inspection of administrative users. It protects all user-management mutations, including `create`/`add`/`new`, `edit`/`update`/`e`/`u`, and `delete`/`rm`/`remove`.


## Accepted grammar

The route is `tea {admin|a} {users|u} [USER]`. `USER` is one non-option detail operand; it is optional, and no second operand is accepted. `list` and `ls` are delegated to the leaf scope.

After `users`/`u`, or after the optional `USER`, each of these may occur zero or more times and consumes exactly one value: `--fields`/`-f`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o`. `--limit`, `--lm`, and the named two-character alias `-lm` are three distinct aliases for the same one-value option and have the same placement. Required values use only `--long VALUE`, `--long=VALUE`, or `-x VALUE`; for the named alias, only `-lm VALUE` is accepted. Attached short values and short-option clusters are forbidden, including clusters that merely contain `-l` and `-m`.

## Outcomes

Allow the exact grammar at EOF under the trusted execution assumption. Defer a child leaf route, every mutation alias, a missing or surplus operand, an unknown or misplaced option, a missing value, attached short form, short cluster, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy has no deny branch.

## Scope limits and non-goals

This scope neither authorizes admin mutations nor validates `USER` or option values, server authorization, or returned data. It assumes normal use of the trusted `bcd62a1` CLI, not attempts to bypass the policy.

Sources: [`cmd/admin.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/admin.go), [`cmd/admin/users/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/admin/users/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
