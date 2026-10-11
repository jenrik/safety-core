# `tea logins helper store` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits only Tea's documented no-op Git credential-helper `store`/`erase` routes. It protects login setup, credential retrieval, login mutation, and every other Tea action from an automatic grant.


## Accepted grammar

The complete route is `tea {logins|login} {helper|git-credential} {store|erase}`. All route aliases are exact. It accepts zero argv operands and no options; no option placement, attached short form, or cluster is accepted. The credential-helper protocol is stdin, not argv, and this policy does not parse or validate that stdin.

## Outcomes

Allow only the exact route at EOF under the trusted execution assumption. Defer every trailing argv word or option, `setup`, `get`, another helper child, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy has no deny branch.

## Scope limits and non-goals

The contract does not authorize credential setup or retrieval, inspect stdin, validate credential protocol fields, or establish remote authorization. It assumes normal use of pinned Tea `bcd62a1`, not adversarial policy evasion.

Source: [`cmd/login/helper.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/login/helper.go).
