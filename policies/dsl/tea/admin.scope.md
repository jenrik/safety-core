# `tea admin` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits only Tea's read-only `admin` help route. It protects administrative-user management and every other administrator action from being treated as an automatic permission grant.


## Accepted grammar

The complete accepted route is `tea {admin|a}` at end of arguments. It has zero operands and no options. `users` and `u` are child-route tokens, not operands accepted by this scope; the `admin-users` and `admin-users-list` scopes own them.

## Outcomes

Allow only the accepted route at EOF under the trusted execution assumption. Defer every child route, option, operand, trailing word, assignment, redirect, inherited `tea` function, path-qualified Tea, and a non-external-path target. This policy has no deny branch; it never returns deny.

## Scope limits and non-goals

This contract does not authorize user creation, update, deletion, other admin subcommands, API calls, or inspect Tea's implementation. It assumes normal, non-adversarial use of the trusted `bcd62a1` CLI and does not attempt to establish the caller's server authorization.

Source: [`cmd/admin.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/admin.go).
