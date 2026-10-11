# Tea Milestones Parent Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

`milestones.policy.json` permits only read-only milestone discovery through Tea's
parent `milestones` command: its implicit list action with no positional operand,
or its detail action for one milestone name. It protects remote milestone lifecycle
state (creation, closure, reopening, and deletion) and issue-to-milestone
assignments from this policy's allow result.

## Trusted Tea boundary

An allow result is valid only for a direct, unqualified bare external executable
spelled `tea`. Assignment-prefixed
commands, redirects, inherited executable functions named `tea`, path
spellings such as `/usr/bin/tea` are outside
this contract and defer. The policy relies on the pinned Tea command definitions:
[`cmd/milestones.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/milestones.go),
[`cmd/milestones/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/milestones/list.go),
and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).

## Mandatory accepted grammar

The top-level route token is exactly one of `{milestones|milestone|ms}`. No
root-level option may precede it. After that route, the policy accepts this grammar:

```text
tea {milestones|milestone|ms} OPTION* [MILESTONE] OPTION*
```

`MILESTONE` is one non-dash shell word. It is optional, has cardinality zero or
one, and may appear before, after, or between accepted options. Zero positional
operands invokes Tea's parent list action; exactly one invokes its milestone-detail
action. A second bare word always defers. Every accepted option may occur zero or
more times and may be interleaved on either side of the optional milestone.

The complete option set is below. Every form requires exactly one value; the policy
does not constrain that value.

| Purpose | Accepted forms | Placement |
| --- | --- | --- |
| Login profile | `--login VALUE`, `--login=VALUE`, `-l VALUE` | Parent or detail |
| Repository | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` | Parent or detail |
| Remote | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` | Parent or detail |
| Output format | `--output VALUE`, `--output=VALUE`, `-o VALUE` | Parent or detail |

This is deliberately narrower than all flags Tea may inherit from its list command:
the parent policy does not allow `--fields`/`-f`, `--state`, `--page`/`-p`,
`--limit`/`--lm`/`-lm`, or any other flag. At `bcd62a1`, the grammar also excludes
short-option clusters, attached short values, and `-x=VALUE`; only the long
separate, long equals, and short separate forms in the table are accepted.

## Excluded routes and inputs

The parent policy must not authorize an explicit child route. It defers the child
tokens and aliases `{list|ls}`, `{create|c}`, `close`, `{delete|rm}`,
`{reopen|open}`, and `{issues|i}`. Consequently it also cannot authorize nested
issue-assignment routes `{add|a}` or `{remove|r}`. Unknown dash-prefixed words,
missing option values, surplus operands, route aliases in the wrong position, and
all other token sequences defer.

## Threat model and non-goals

This contract assumes ordinary, non-adversarial use of a compatible Tea `bcd62a1`
binary. It does not prove server authorization, repository selection, login
identity, option or milestone-name validity, command success, or the contents of
remote responses. It does not govern other executables, direct API transports, or
an intentionally incompatible Tea binary. Child read routes are separately
scoped; their exclusion here preserves route-specific review boundaries.

## Decision outcome

Only a complete invocation satisfying the trusted boundary and mandatory grammar
is allowed, with reason `tea milestones is read-only`. Every mismatch or exclusion
defers to another policy or the harness. This policy never returns `deny`.
