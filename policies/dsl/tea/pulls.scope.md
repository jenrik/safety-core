# Tea Pulls Parent Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

`pulls.policy.json` permits only read-only pull-request discovery through Tea's
parent `pulls` command: its implicit list action with no positional operand, or
its detail action for one pull index. It protects remote pull-request lifecycle
and review state from mutation, and local checkout state from the `checkout` and
`clean` child actions.

## Trusted Tea boundary

An allow result is valid only for a direct, unqualified bare external executable
spelled `tea`. Assignment-prefixed
commands, redirects, inherited executable functions named `tea`, path
spellings such as `/usr/bin/tea` are outside
this contract and defer. The policy relies on the pinned Tea command definition
in [`cmd/pulls.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/pulls.go).

## Mandatory accepted grammar

The top-level route token is exactly one of `{pulls|pull|pr}`. No root-level
option may precede it. After that route, the policy accepts this grammar:

```text
tea {pulls|pull|pr} OPTION* [PULL OPTION*]
```

`PULL` is one non-dash shell word that is not a reserved child-route token. It
is optional, has cardinality zero or one, and may appear before, after, or
between accepted options. Zero positional operands invokes Tea's implicit parent
list action; exactly one invokes its pull-detail action. A second bare word
always defers. Every accepted option may occur zero or more times and may be
interleaved on either side of the optional pull operand.

The complete option set is below. Every form requires exactly one value; the
policy does not constrain that value.

| Purpose | Accepted forms | Placement |
| --- | --- | --- |
| Login profile | `--login VALUE`, `--login=VALUE`, `-l VALUE` | Parent or detail |
| Repository | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` | Parent or detail |
| Remote | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` | Parent or detail |
| Output format | `--output VALUE`, `--output=VALUE`, `-o VALUE` | Parent or detail |

This is deliberately narrower than the flags Tea exposes through its parent and
inherited `bcd62a1` pull-list command. The parent policy does not allow
`--comments`, `--fields`/`-f`, `--state`, `--page`/`-p`,
`--limit`/`--lm`/`-lm`, or any other option. It also excludes short-option
clusters, attached short values, and `-x=VALUE`; only the long separate, long
equals, and short separate forms in the table are accepted.

## Excluded routes and inputs

The parent policy must not authorize an explicit child route. It defers every
child token and alias defined by the pinned command:
`{list|ls}`, `{checkout|co}`, `clean`, `{create|c}`, `close`, `{reopen|open}`,
`{edit|e}`, `review`, `{approve|lgtm|a}`, `reject`, `{merge|m}`, `reply`,
`{review-comments|rc}`, `resolve`, and `unresolve`. Consequently, `list` and
`review-comments` remain subject to their separate, route-specific policies, and
none of the mutating child actions can inherit this parent's allow result.

Unknown dash-prefixed words, missing option values, surplus operands, child
aliases in the operand position, route aliases in the wrong position, and all
other token sequences defer.

## Threat model and non-goals

This contract assumes ordinary, non-adversarial use of a compatible Tea
`bcd62a1` binary. It does not prove server authorization, repository selection,
login identity, pull-index or option-value validity, command success, or the
contents of remote responses. It does not govern other executables, direct API
transports, or an intentionally incompatible Tea binary. It neither
authorizes nor validates any child route; those routes require their own policy
review.

## Decision outcome

Only a complete invocation satisfying the trusted boundary and mandatory grammar
is allowed, with reason `tea pulls is read-only`. Every mismatch or exclusion
defers to another policy or the harness. This policy never returns `deny`.
