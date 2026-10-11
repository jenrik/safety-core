# `tea releases assets` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This policy permits only Tea's read-only release-asset parent action, which
lists the assets for releases. It protects remote release assets from the
child actions that create or delete them.


## Accepted grammar

The only route is:

```text
tea {releases|release|r} [DEFAULT_FLAG ...] {assets|asset|a} [DEFAULT_FLAG ...]
```

The route has zero positional operands. `DEFAULT_FLAG` may occur zero or more
times in either shown position, including interleaved with other default flags.
Each occurrence is exactly one of the following required-value options:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Each option consumes exactly one value. Long options permit only separate and
`=` forms; ordinary short options permit only separate forms. Attached short
values, `-x=VALUE`, and every short-option cluster defer. No option is
accepted before `{releases|release|r}`. This matches the default flags
registered on both pinned Tea route nodes and the policy's `releases` and
`parent` option placement.

## Excluded syntax

`{list|ls}`, `{create|c}`, and `{delete|rm}` are child routes and always defer
from this policy. The child routes have their own policies; specifically,
`create` and `delete` mutate remote release assets. Any other child token,
positional operand, `--`, unknown option, missing option value, malformed
option form, or option outside the accepted positions also defers.

## Outcomes

- **allow:** the complete accepted grammar reaches EOF under the trusted
  execution assumption.
- **defer:** every excluded or malformed form, and every untrusted execution
  target or shell context.
- **deny:** none.

## Scope limits and threat model

The policy relies on the parent action and `flags.AllDefaultFlags` in pinned
Tea `bcd62a1` being read-only. It does not validate flag values, repository or
login selection, credentials, remote authorization, asset metadata, Tea/API
success, or the behavior of a replacement binary. It models ordinary,
non-adversarial agent use; deliberate evasion through another executable or a
bespoke API client is out of scope.

Sources: [`cmd/attachments.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments.go),
[`cmd/attachments/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments/list.go),
[`cmd/attachments/create.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments/create.go),
[`cmd/attachments/delete.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/attachments/delete.go),
and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
