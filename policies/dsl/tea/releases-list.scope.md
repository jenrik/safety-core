# `tea releases list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This policy permits only read-only enumeration of a repository's releases. It protects remote release state: release records, release metadata, and release assets from creation, editing, deletion, upload, download, or other mutation routes. It does not grant access to, or permission to alter, any protected asset.


## Accepted grammar

The top-level command token must be `tea`, immediately followed by one of `releases`, `release`, or `r`. Root-level options are not accepted.

At the `releases`/`release`/`r` level, zero or more of the following parent options may occur before the leaf command:

`--login VALUE`, `--login=VALUE`, or `-l VALUE`

`--repo VALUE`, `--repo=VALUE`, or `-r VALUE`

`--remote VALUE`, `--remote=VALUE`, or `-R VALUE`

`--output VALUE`, `--output=VALUE`, or `-o VALUE`

The next route token must be `list` or `ls`. There are no positional operands.

After `list`/`ls`, zero or more parent options above may occur, together with these leaf-only pagination options:

`--page VALUE`, `--page=VALUE`, or `-p VALUE`

`--limit VALUE`, `--limit=VALUE`, `--lm VALUE`, `--lm=VALUE`, or `-lm VALUE`

Every accepted option requires exactly one value. Long options accept a separate value or an `=` value; short options accept only a separate value. `-lm` is one named short alias, not a short-option cluster, and accepts only a separate value. The policy imposes no maximum cardinality: every accepted option may repeat at its permitted placement.

## Parser and Tea compatibility

This grammar intentionally follows the option forms represented by `releases-list.policy.json`: `separate` and `equalsLong`. It does not accept short clusters, attached short values, or `-x=VALUE`; accepting the latter in the DSL would also admit unsupported attached short values. Tea `bcd62a1` exposes the parent route aliases and default flags in [`cmd/releases.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/releases.go), and exposes the `list`/`ls` leaf, pagination flags, and no-operand action in [`cmd/releases/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/releases/list.go).

## Threat model and non-goals

The threat model covers natural use of the Tea CLI, including its documented route aliases and option spellings. It does not defend against an adversarial agent intentionally substituting another executable, transport, or direct Gitea API request to evade this policy. Tea, not this policy, validates option values, repository context, authentication, authorization, pagination semantics, output formatting, and returned data. This policy neither inspects results nor guarantees that the server honors the read-only request.

## Outcomes

Allow occurs only at end of input when the complete accepted grammar runs within the execution boundary. Every other form defers, including missing or extra route tokens, positional operands, root-level options, unknown or misplaced options, missing option values, malformed or unsupported option forms, release-asset or release-mutation routes, direct Tea assignments or redirects, inherited functions, path-qualified Tea, non-external-path targets, and execution-boundary mismatches. This policy never returns deny.
