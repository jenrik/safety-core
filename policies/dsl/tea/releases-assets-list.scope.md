# `tea releases assets list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This scope permits only read-only enumeration of the attachments belonging to one remote release. It protects remote release assets from creation, replacement, deletion, and every other unreviewed release-asset operation. The pinned implementation first resolves the release by tag, then calls `ListReleaseAttachments`; it does not download an asset.


## Accepted grammar

The route is exactly `tea {releases|release|r} {assets|asset|a} {list|ls} TAG`, where `TAG` is exactly one non-option operand. There are no root-level options: the first argument after `tea` must be a release-route alias.

The required-value default options are `--login`/`-l`, `--repo`/`-r`, `--remote`/`-R`, and `--output`/`-o`. Each may occur zero or more times after the release-route alias: between the release and asset aliases, between the asset and list aliases, between the list alias and `TAG`, or after `TAG`.

The required-value pagination options are `--page`/`-p` and `--limit`/`--lm`/named `-lm`. Each may occur zero or more times only between the list alias and `TAG`, or after `TAG`.

Every accepted long option takes either a separate value (`--name VALUE`) or an equals value (`--name=VALUE`). The ordinary short aliases take only a separate value (`-x VALUE`), and named `-lm` takes only `-lm VALUE`. Short clusters and attached short values, including `-lm=VALUE`, defer. The policy does not constrain option values or reject duplicate options.

## Outcomes

Allow only a complete invocation of this grammar at EOF under the trusted execution assumption. Defer a missing tag, an option-looking tag, extra operand, route or alias mismatch, root-level option, unknown option, option in a disallowed position, malformed option form, short cluster, attached short value, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy never denies.

## Threat model and non-goals

The threat model is ordinary use of a Tea-compatible `bcd62a1` CLI, not adversarial attempts to evade policy matching through a different executable or transport. This contract does not validate the tag or option values, repository and login selection, server authorization, response content, or the existence of the selected release or attachments. It does not grant permission for any asset mutation or for any other Tea route.

Sources: [`cmd/releases.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/releases.go), [`cmd/attachments.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments.go), [`cmd/attachments/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
