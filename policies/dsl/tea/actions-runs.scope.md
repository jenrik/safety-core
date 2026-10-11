# `tea actions runs` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy permits only Tea's parent Actions-run route, whose default action at
Tea commit `bcd62a1` is run listing. The protected asset is repository workflow
run state, including cancellation and deletion. The policy MUST NOT permit a
child route or any run mutation.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go),
[`cmd/actions/runs.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/runs.go),
and [`cmd/actions/runs/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/runs/list.go).


## Accepted grammar

The complete permitted argv grammar is:

```text
tea {actions|action} ACTIONS_OPTION* {runs|run} RUNS_OPTION*
```

The command MUST end immediately after the final `RUNS_OPTION`; no positional
operand is accepted. `ACTIONS_OPTION` is accepted only after `{actions|action}`
and before `{runs|run}`. `RUNS_OPTION` is accepted only after `{runs|run}`.
Each option occurrence requires exactly one value and may occur zero or more
times in either allowed position. Values have no policy-level semantic,
repository, login, or output validation; the required value is one argv word,
including `--` when supplied as a separate value.

| Option | Accepted spellings | Accepted forms | Accepted placement | Cardinality |
| --- | --- | --- | --- | --- |
| login | `--login` | `--login VALUE`, `--login=VALUE` | `ACTIONS_OPTION`, `RUNS_OPTION` | zero or more |
| repo | `--repo` | `--repo VALUE`, `--repo=VALUE` | `ACTIONS_OPTION`, `RUNS_OPTION` | zero or more |
| output | `--output`, `-o` | `--output VALUE`, `--output=VALUE`, `-o VALUE` | `ACTIONS_OPTION`, `RUNS_OPTION` | zero or more |

Only long options accept the `=VALUE` form. The inherited Actions options do
not include `-l`, `-r`, `--remote`, or `-R`. Short attached values, including
`-oVALUE` and `-o=VALUE`, and all short clusters MUST defer. Root-level options
before `{actions|action}` MUST defer. The policy does not apply an option
terminator rule: `--` is an ordinary argv word unless consumed as a separate
option value.

## Explicit outcomes

- **permit:** An invocation matching the complete grammar at argv EOF, with the trusted execution assumptions satisfied. This includes both top-level aliases (`actions`, `action`), both parent aliases (`runs`, `run`), every tabled option spelling, and only the tabled forms and placements.
- **defer:** Every non-permitted form. This includes missing route words or option values; any operand; root-level, unknown, malformed, attached-short, or clustered option; a valid option in no permitted position; all child routes; a path-qualified or non-external target; an assignment; a redirection; and an inherited `tea` function. In particular, `list`/`ls`, `view`/`show`/`get`, `delete`/`remove`/`rm`/`cancel`, and `logs`/`log` defer.
- **deny:** No invocation is denied by this policy.

## Exclusions, threat model, and non-goals

This is a permission recognizer, not authorization for repository access. It
does not validate option values, repository selection, credentials, server
permissions, returned run data, output handling, or API success. It does not
inspect alternate CLIs, direct HTTP/API calls, or attempts to
evade recognition. The threat model is ordinary use of a Tea-compatible external
`tea` at commit `bcd62a1`, not adversarial substitution or bypass.
