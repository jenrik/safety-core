# `tea actions` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy permits only Tea's parent Actions route, whose default action at Tea
commit `bcd62a1` displays the Actions subcommand help. The protected assets are
repository Actions secrets, variables, workflow runs, workflow configuration,
and workflow execution. The policy MUST NOT permit an Actions child route.

Source: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go).


## Accepted grammar

The complete permitted argv grammar is:

```text
tea {actions|action} ACTIONS_OPTION*
```

The command MUST end immediately after the final `ACTIONS_OPTION`; it accepts
zero positional operands. `ACTIONS_OPTION` is accepted only after
`{actions|action}`. Every option occurrence consumes exactly one value, may
occur zero or more times, and may be interleaved with every other tabled option.
Values have no policy-level semantic, repository, login, or output validation;
the required value is one argv word, including `--` when supplied as a separate
value.

| Option | Accepted spellings | Accepted forms | Accepted placement | Cardinality |
| --- | --- | --- | --- | --- |
| login | `--login` | `--login VALUE`, `--login=VALUE` | `ACTIONS_OPTION` | zero or more |
| repo | `--repo` | `--repo VALUE`, `--repo=VALUE` | `ACTIONS_OPTION` | zero or more |
| output | `--output`, `-o` | `--output VALUE`, `--output=VALUE`, `-o VALUE` | `ACTIONS_OPTION` | zero or more |

Only long options accept the `=VALUE` form. The Actions parent has no `-l`,
`-r`, `--remote`, or `-R` form. Short attached values, including `-oVALUE` and
`-o=VALUE`, and all short clusters MUST defer. Root-level options before
`{actions|action}` MUST defer. The policy does not apply an option terminator
rule: `--` is an ordinary argv word unless consumed as a separate option value.

## Explicit outcomes

- **permit:** An invocation matching the complete grammar at argv EOF, with the trusted execution assumptions satisfied. This includes both route aliases (`actions`, `action`), every tabled option spelling, and only the tabled forms and placement.
- **defer:** Every non-permitted form. This includes a missing route word or option value; any operand; root-level, unknown, malformed, attached-short, or clustered option; all child routes; a path-qualified or non-external target; an assignment; a redirection; and an inherited `tea` function. In particular, `secrets`/`secret`, `variables`/`variable`/`vars`/`var`, `runs`/`run`, and `workflows`/`workflow` defer.
- **deny:** No invocation is denied by this policy.

## Exclusions, threat model, and non-goals

This is a permission recognizer, not authorization for repository access. It
assumes Tea `bcd62a1` retains the documented help-only parent default. It does
not validate option values, repository selection, credentials, server
permissions, help output, output handling, or API success. It does not inspect
alternate CLIs, direct HTTP/API calls, or attempts to evade
recognition. The threat model is ordinary use of a Tea-compatible external
`tea` at commit `bcd62a1`, not adversarial substitution or bypass.
