# `tea ssh-keys list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits listing account SSH keys without authorizing the `add`, `delete`, or `rm` operations that alter authentication material.


## Accepted grammar

The complete route is `tea {ssh-keys|ssh-key} {list|ls}` with zero operands. After the parent or leaf, `--login`/`-l`, `--output`/`-o`, and `--page`/`-p` each take exactly one value and may repeat. `--limit`, `--lm`, and named `-lm` are one-value limit aliases with the same placement. Long aliases permit `--long VALUE` and `--long=VALUE`; ordinary short aliases permit `-x VALUE`; named `-lm` permits only `-lm VALUE`. All attached short forms and other short clusters are forbidden.

## Outcomes

Allow only that grammar at EOF under the trusted execution assumption. Defer operands, another route, unknown or misplaced option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. No deny result exists.

## Scope limits and non-goals

The scope does not authorize key changes, validate remote access, or inspect key content. It is limited to normal use of pinned Tea `bcd62a1`.

Source: [`cmd/sshkeys/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/sshkeys/list.go).
