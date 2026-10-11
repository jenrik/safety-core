# `tea ssh-keys` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits Tea's read-only SSH-key listing parent route. It protects SSH-key addition and removal, which change account authentication material.


## Accepted grammar

The parent route is `tea {ssh-keys|ssh-key}` with zero operands; `list`/`ls` is delegated to `ssh-keys-list`. At the parent only, `--login`/`-l`, `--output`/`-o`, and `--page`/`-p` each take one value and may repeat. `--limit`, `--lm`, and named alias `-lm` are one-value aliases with the same placement and cardinality. Long aliases allow separate or `=` values; ordinary short aliases allow only separate values; named `-lm` allows only `-lm VALUE`. No attached short values or short clusters are accepted.

## Outcomes

Allow only the parent grammar at EOF under the execution boundary. Defer the list child for its leaf policy, `add`, `delete`, `rm`, operands, unknown or misplaced options, malformed values, direct Tea assignments or redirects, inherited functions, path-qualified Tea, non-external-path targets, and execution-boundary mismatches. This policy never denies.

## Scope limits and non-goals

It does not authorize SSH-key mutation, validate selector values, expose key material, or establish server authorization. It covers ordinary use of Tea `bcd62a1`, not adversarial policy evasion.

Sources: [`cmd/sshkeys.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/sshkeys.go) and [`cmd/sshkeys/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/sshkeys/list.go).
