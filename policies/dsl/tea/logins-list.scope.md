# `tea logins list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This scope permits the read-only listing of persisted Tea login configuration while not authorizing login creation, modification, deletion, default selection, credential-helper use, token refresh, or a single-login detail lookup. Tea `bcd62a1` implements the leaf by reading `config.GetLogins()` and printing the result; it does not make a Gitea API request. Sources: [`cmd/login.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/login.go) and [`cmd/login/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/login/list.go).


## Accepted grammar

The route is exactly `tea {logins|login} {list|ls}`. The top-level token must be first: root-level options are not accepted. There are zero positional operands, including after `list` or `ls`.

At either the parent position (between `{logins|login}` and `{list|ls}`) or the leaf position (after `{list|ls}`), the policy accepts each of these required-value option families zero or more times, in any order and interleaved with the route tokens:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Each `VALUE` is exactly one argv token and is otherwise unconstrained by this policy. Repeating an option, including with a different value, is allowed; the policy imposes no cardinality limit. Attached short values, `-x=VALUE`, and every short-option cluster defer. The accepted option grammar is the policy's complete allowlist; Tea remains responsible for deciding whether an accepted value or option placement is meaningful.

## Threat model and non-goals

The contract covers ordinary use of a Tea-compatible external CLI, not adversarial attempts to evade policy with another executable or transport. It does not validate option values, redact login metadata, inspect Tea's local configuration, establish remote authorization, or authorize any sibling `logins` operation.

## Outcomes

Allow only a complete accepted grammar at EOF. Any missing option value, unknown or misplaced option, malformed option form, positional operand, or route mismatch defers. This policy has no deny outcome.
