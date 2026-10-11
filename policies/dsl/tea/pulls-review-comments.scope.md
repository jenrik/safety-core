# `tea pulls review-comments` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only retrieval of review comments for one pull request. It protects pull-review comments and the wider pull-review state from creation, reply, review, resolve, unresolve, approval, rejection, merge, edit, close, reopen, checkout, and every other route outside the grammar below.


## Accepted grammar

The complete permitted grammar is:

```text
tea {pulls|pull|pr} [DEFAULT_OPTION ...] {review-comments|rc} [DEFAULT_OPTION ...] PULL_INDEX [DEFAULT_OPTION ...]
```

`PULL_INDEX` is exactly one non-option word. It must occur after `review-comments` or `rc`; a missing index, an index beginning with `-`, or any additional non-option word defers. Option values are not validated and are not route operands.

`DEFAULT_OPTION` is exactly one of the following options, each with one required value:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Each default option may repeat and may be interleaved only after the `pulls`/`pull`/`pr` parent, after the `review-comments`/`rc` leaf, or after `PULL_INDEX`. No option is accepted before the parent route token. Long options accept separate and `=` forms; short aliases accept only a separate value. Short clusters, attached short values, and `-x=VALUE` forms defer.

At pinned Tea commit `bcd62a1`, `review-comments` is aliased as `rc`, takes one pull index, and lists review comments. Tea also exposes its `--fields` flag on this command, but `pulls-review-comments.policy.json` does not permit that flag; `--fields` and every other upstream flag defer. The parent aliases are `pulls`, `pull`, and `pr`.

## Outcomes

Allow only a complete invocation matching the grammar at end of arguments and the trusted execution assumption. Defer every other invocation: a wrong or incomplete route, omitted or surplus operand, unknown or misplaced option, missing option value, unsupported option form, root-level option, assignment, redirect, inherited function, non-direct executable, or execution target other than `external-path`. This policy has no deny outcome.

## Threat model and non-goals

This contract assumes normal, non-adversarial use of a Tea-compatible executable at commit `bcd62a1`; it does not attempt to prevent deliberate bypasses through a different program or direct API access. It does not validate pull-index or option values, confirm the selected repository or login, constrain returned review-comment data, inspect API responses, establish Gitea authorization, or grant mutation privileges.

Sources: [`cmd/pulls.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/pulls.go) and [`cmd/pulls/review_comments.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/pulls/review_comments.go).
