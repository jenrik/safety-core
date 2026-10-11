# `tea actions workflows` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This policy permits only Tea's default repository-workflow listing route. At
Tea commit `bcd62a1`, `runWorkflowsDefault` calls `RunWorkflowsList`, which
lists repository workflows. The protected assets are repository workflow
configuration, enabled/disabled state, and workflow execution: dispatching a
workflow or changing its enabled state is not permitted by this policy.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go),
[`cmd/actions/workflows.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/workflows.go),
and [`cmd/actions/workflows/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/workflows/list.go).


## Complete policy-recognized grammar

The policy-recognized route is:

```bash
tea {actions|action} ACTIONS_OPTION* {workflows|workflow} WORKFLOWS_OPTION*
```

`actions` and `action` are the complete set of accepted top-level route
aliases. `workflows` and `workflow` are the complete set of accepted
namespace aliases. The command must end after the zero-or-more options; it
accepts no operands, no `--` terminator, and no child route.

`ACTIONS_OPTION*` appears only after `actions` or `action` and before
`workflows` or `workflow`. `WORKFLOWS_OPTION*` appears only after
`workflows` or `workflow`. In either placement, each occurrence is exactly
one of the following required-value options:

| Option family | Accepted spellings and forms |
| --- | --- |
| login | `--login VALUE`, `--login=VALUE` |
| repository | `--repo VALUE`, `--repo=VALUE` |
| output | `--output VALUE`, `--output=VALUE`, `-o VALUE` |

Every occurrence consumes exactly one value. For a separate form, `VALUE` is
the immediately following single argument word; this policy does not restrict
its contents, so an empty or dash-prefixed word is still a policy value. For
an equals form, `VALUE` is the substring after `=` and may be empty. Each
option family has unbounded zero-or-more cardinality in each allowed
placement, and families may be interleaved. No option is accepted before the
top-level route alias.

Only long option names accept the equals form. The inherited Actions options do
not include `-l`, `-r`, `--remote`, or `-R`. Attached short values, including
`-oVALUE`, short equals forms including `-o=VALUE`, and every short-option
cluster are outside this grammar.

## Explicit outcomes

- **permit:** only the complete grammar above at end of arguments, subject to
  the trusted execution assumption.
- **defer:** every other invocation. This includes root-level options;
  operands; unknown options; missing required values; attached, equals-short,
  or clustered short forms; malformed route order; and all child routes. The
  recognized child-route tokens that defer are `list`/`ls`, `view`/`show`/`get`,
  `dispatch`/`trigger`/`run`, `enable`, and `disable`. It also includes every
  invocation outside the trusted execution assumption.
- **deny:** none. This policy has no deny branch.

## Exclusions, threat model, and non-goals

The policy does not authorize any workflow dispatch, enablement, disablement,
or other workflow mutation. It does not validate option values, repository
selection, credentials, local context, returned workflow data, Tea's API
request, or API success. It does not authorize another Tea command, another
API client, or a replacement `tea` executable.

The threat model is normal use of the pinned, trusted Tea CLI. Deliberately
substituting a different executable or client to evade this recognizer is out
of scope.
