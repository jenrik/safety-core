# `tea webhooks` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only enumeration or detail inspection of webhooks. It protects webhook creation, update, and deletion, which can change remote delivery behavior.


## Accepted grammar

The direct parent route is `tea {webhooks|webhook|hooks|hook} [WEBHOOK_ID]`.
`WEBHOOK_ID` is an optional single non-option detail operand; no second operand
is accepted. When it recognizes `list` or `ls`, the direct parent policy returns
`ignore`, not `defer`, so the aggregate profile can evaluate `webhooks-list`.
The parent does not validate tokens after that ignored child alias.

Before the ignored child alias, and after `WEBHOOK_ID`, each of
`--repo`/`-r`, `--org`, `--remote`/`-R`, `--login`/`-l`, `--output`/`-o`, and
`--page`/`-p` may repeat and requires one value. `--limit`, `--lm`, and named
`-lm` are one-value aliases with the same placement. `--global` may repeat at
those positions but takes no value. The full list-child grammar, including
options after `list`/`ls`, belongs to `webhooks-list.scope.md`.

## Outcomes

Allow the direct parent or detail grammar at EOF under the trusted execution
assumption. Return `ignore` for `list`/`ls`; the aggregate profile permits that
route only when `webhooks-list` allows its complete leaf grammar. Defer
`create`/`c`, `delete`/`rm`, `update`/`edit`/`u`; surplus operands; unknown or
misplaced options before a recognized child alias; malformed values;
assignments; redirects; inherited functions; and target mismatch. This policy
has no deny branch.

## Scope limits and non-goals

This scope does not authorize delivery changes, validate webhook IDs or routing selectors, or inspect remote response content. It assumes normal use of Tea `bcd62a1`, not adversarial attempts to evade the recognizer.

Sources: [`cmd/webhooks.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/webhooks.go) and [`cmd/webhooks/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/webhooks/list.go).
