# `tea milestones issues` Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Mandatory contract

This document is the mandatory scope contract for
`milestones-issues.policy.json`. The policy permits only a direct,
unqualified bare external executable whose basename is `tea` and whose behavior
is compatible with Tea source commit
[`bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68).
Same-named executables, shell functions inherited as `tea`, and incompatible
Tea versions are outside this assurance.

The protected asset is issue-to-milestone assignment state. The intended
outcome is a read of the issues and pull requests assigned to one milestone;
the policy must not permit assigning or unassigning an issue or pull request.

## Exact accepted command language

The accepted command language is:

```text
tea P O* C O* M O*
```

`P` is exactly one parent-route token: `milestones`, `milestone`, or `ms`.
`C` is exactly one child-route token: `issues` or `i`. The aliases are defined
by Tea's [`cmd/milestones.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/milestones.go)
and [`cmd/milestones/issues.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/milestones/issues.go).

`M` is exactly one milestone-name operand. It must be a token that does not
start with `-` and is not exactly `add`, `a`, `remove`, or `r`. This deliberate
reservation means that otherwise valid milestones with one of those four names
defer rather than being permitted as reads. There are no other bare operands:
zero, two, or more milestone operands defer.

`O` is any one of the following options, with a required value:

| Option | Accepted forms |
| --- | --- |
| login | `--login VALUE`, `--login=VALUE`, `-l VALUE` |
| repository | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` |
| remote | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` |
| output | `--output VALUE`, `--output=VALUE`, `-o VALUE` |

Options may occur before `C`, before `M`, or after `M`, exactly as the three
`O*` positions show. Each position accepts zero or more options in any order.
The policy imposes no uniqueness or maximum-occurrence rule: every listed
option may repeat, including across positions. A required option value is
consumed as its value; Tea, not this policy, validates the value and determines
the effect of duplicates. These are Tea's shared default flags, defined in
[`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).

Only the listed forms are accepted. Long options support separate and
`--long=value` forms; short options support only separate values. Short-option
clusters, attached short values, `-x=VALUE`, missing option values, and unknown
options defer. Root-level options before `P` are unsupported by Tea at the
pinned revision and defer.

The policy intentionally does not admit the route-local Tea flags
`--state`, `--kind`, `--page|-p`, `--limit|--lm`, or `--fields|-f`, even though
the pinned command defines them. It also does not admit the `add|a` or
`remove|r` child routes, which call Tea's issue-edit API to assign or remove a
milestone.

## Threat model and non-goals

The model is non-adversarial, natural CLI use. The policy structurally rejects
assignments, redirections, and inherited `tea` shell functions so that a
permitted command is a direct external Tea invocation. Alternative executable
spellings, a malicious replacement named `tea`, and attempts to bypass this
route using another client or raw API are outside the model.

This policy does not validate repository context, login selection, remote
selection, output format, milestone existence, command results, or Tea's
interpretation of repeated flags. It is not a general Tea read policy and does
not widen this command to Tea's omitted filters, pagination, field selection,
or any mutation.

## Decisions

The policy returns `allow` only when the complete accepted language reaches the
end of the argument list with no assignment, redirection, or inherited `tea`
function. Every other invocation defers to the harness's normal permission
handling. This policy never returns `deny`.
