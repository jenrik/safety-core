# `tea issues` Parent Read Policy Contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

`issues.policy.json` authorizes only Tea's implicit issue reads: listing when
the parent command has no issue operand, and showing one issue when it has one
operand. The protected asset is remote issue state. This policy must not
authorize creating an issue, editing an issue, reopening an issue, or closing
an issue.


## Pinned Tea routes

Tea `bcd62a1` defines the parent command in
[`cmd/issues.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/issues.go):

- Parent names: `issues`, `issue`, and `i`.
- Implicit parent read: no issue operand lists issues; one issue operand shows
  issue detail.
- Child names that this parent policy excludes: `list` and `ls`; `create` and
  `c`; `edit` and `e`; `reopen` and `open`; and `close` (which has no alias).

The first argument after `tea` must be one of the three parent names. Root
options before that name are not accepted. A child name is never accepted as
the optional issue operand, even where Tea would dispatch that name as a child
route. The explicit `tea {issues|issue|i} {list|ls}` read route belongs to
`issues-list.policy.json`, not to this contract.

## Accepted grammar

The only permitted complete forms are, with options placed at any position
where `OPTIONS` appears:

```text
tea {issues|issue|i} OPTIONS
tea {issues|issue|i} OPTIONS ISSUE OPTIONS
```

`ISSUE` is exactly one statically known, non-dash argument which is not any
excluded child name above. The policy does not validate that it is a numeric
issue index; Tea validates it. A second bare argument is not permitted.

`OPTIONS` is zero or more occurrences of these required-value options. Each
option may repeat without a policy cardinality limit; its value is not
validated, constrained, or retained by the policy.

| Option names | Accepted forms | Placement |
| --- | --- | --- |
| `--login`, `-l` | `--login VALUE`, `--login=VALUE`, `-l VALUE` | Parent state before `ISSUE`, or detail state after `ISSUE` |
| `--repo`, `-r` | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` | Parent state before `ISSUE`, or detail state after `ISSUE` |
| `--remote`, `-R` | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` | Parent state before `ISSUE`, or detail state after `ISSUE` |
| `--output`, `-o` | `--output VALUE`, `--output=VALUE`, `-o VALUE` | Parent state before `ISSUE`, or detail state after `ISSUE` |

For a separate form, `VALUE` is the immediately following statically known
argument and is consumed as the option value even if it begins with `-` or is a
child name. For a long equals form, the text after `=` is the value, including
an empty value. Thus option placement and values may be interleaved with the
single `ISSUE` operand, but only one non-option argument may remain after all
option values are consumed.

The policy intentionally accepts no other Tea flags on this parent route,
including Tea's `--comments` and issue-list filter/pagination flags. It
accepts neither short-option clusters nor attached short values: `-lr VALUE`,
`-lVALUE`, and `-l=VALUE` defer. Only the long names have equals forms.

## Exclusions, assumptions, and non-goals

Unknown options, missing required option values, an unknown or unresolved
argument, `--`, extra operands, and every excluded child route defer. The
policy does not validate login names, repositories, remotes, output formats,
issue indices, remote authorization, server responses, or Tea's network
behavior. It assumes ordinary, non-adversarial use of a Tea-compatible binary
at the pinned commit; direct API calls and deliberate policy-evasion transports
are outside the threat model.

## Permit, defer, and deny

Permit only a complete invocation satisfying the trusted boundary and accepted
grammar above. Defer every other invocation, including all mutation routes and
all unsupported syntax. This policy never returns `deny`.
