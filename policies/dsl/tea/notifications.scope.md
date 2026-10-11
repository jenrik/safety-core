# `tea notifications` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits Tea's read-only notification listing parent route. It protects notification state changes: `read`/`r`, `unread`/`u`, `pin`/`p`, and `unpin`.


## Accepted grammar

The parent route is `tea {notifications|notification|n}` with zero operands. `ls`/`list` is a child route delegated to `notifications-ls`. At the parent only, the following may each occur zero or more times: one-value `--fields`/`-f`, `--types`/`-t`, `--states`/`-s`, `--page`/`-p`, `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o`; one-value `--limit`, `--lm`, and named `-lm`; and valueless `--mine`/`-m`. Required long aliases use separate or `=` values, ordinary short aliases use separate values, and named `-lm` uses only `-lm VALUE`. `--mine` and `-m` take no value. No attached short values or short clusters are accepted; named `-lm` is an explicit alias, not a cluster.

## Outcomes

Allow only the parent grammar at EOF under the trusted execution assumption. Defer child syntax for its leaf policy, all state-changing children, any operand, unknown or misplaced option, valueless flag with a value, malformed required value, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Scope limits and non-goals

It does not authorize notification updates, validate filter values, inspect notification contents, or establish remote authorization. It models ordinary use of pinned Tea `bcd62a1`, not adversarial evasion.

Sources: [`cmd/notifications.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/notifications.go), [`cmd/notifications/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/notifications/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
