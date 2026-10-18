# Tea Logins Helper Get Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

`logins-helper-get.policy.json` is a guard policy that protects stored and
refreshed access tokens by classifying credential retrieval as deferred. It
never grants the route.

## Exact scope and aliases

The exact recognized route is `tea {logins|login} {helper|git-credential} get`. Upstream reads credential input, may refresh OAuth state, and writes a password token in [`cmd/login/helper.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/login/helper.go).

## Exclusions and threat model

Every invocation, including exact route matches, defers. Alternate executables are outside the non-adversarial threat model.

## Assumptions and non-goals

This policy neither parses stdin nor attempts credential redaction.

## Permit/defer/deny behavior

This guard policy has no permit path and no deny path. Exact and mismatched
routes both defer. The parent `logins-helper.policy.json` permission policy also
defers the `get` subcommand, so no Tea permission policy covers the credential
retrieval route.
