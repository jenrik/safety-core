# `tea labels` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits Tea's default label read at the `labels` parent route. It
protects remote label mutation and the local file written by Tea's label export
operation.


## Accepted grammar

The complete parent route is `tea {labels|label}` with zero non-option
operands. After either parent alias and before EOF, the following options may
appear in any order and may each repeat:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Each accepted option consumes exactly one value. No option is accepted before
the parent route, after a child route, or as an operand. Attached short values,
short `=` values, and short-option clusters are not accepted.

`--save` and `-s` are the only recognized valueless save spellings. They may
occur at the parent-option position and may repeat, but each sets the policy's
save marker, so the completed invocation defers rather than allowing. No
value-bearing save form is accepted. This excludes Tea's `LabelsExport` local
write path.

## Outcomes

Allow only a complete, direct, non-save parent invocation under the trusted
execution assumption. Defer `list`/`ls` for `labels-list`, mutation children
`create`/`c`, `update`, `delete`, and `rm`, every non-option operand, unknown
or misplaced option, malformed option form, save-bearing form, direct Tea
assignment or redirect, inherited function, and unverified execution shape. This
policy never denies.

## Scope limits and threat model

The contract does not authorize label creation, update, deletion, export, or
any other Tea command; validate repository, login, remote, output, or option
values; inspect labels or output; establish remote authorization; or determine
Tea command success. It covers ordinary, non-adversarial use of the pinned Tea
CLI, not deliberate policy-evasion attempts using a different executable or an
incompatible `tea` implementation.

Sources: [`cmd/labels.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/labels.go) and [`cmd/labels/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/labels/list.go).
