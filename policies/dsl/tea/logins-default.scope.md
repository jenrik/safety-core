# Tea Logins Default Policy Scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Mandatory contract

`logins-default.policy.json` grants automatic permission only to inspect Tea's
persisted default-login selection. It must not grant permission to select or
change that default login.


## Accepted invocation grammar

The complete route is:

```text
tea {logins|login} [CONTEXT-OPTION ...] default [CONTEXT-OPTION ...]
```

`logins` and `login` are the only accepted top-level aliases. `default` is the
only accepted leaf token. There are no positional operands: specifically, a
word after `default` that is not consumed as an accepted option is not allowed.
At Tea `bcd62a1`, that operand selects a login and invokes `SetDefaultLogin`;
the zero-operand form reads the current default. Source:
[`cmd/login/default.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/login/default.go).

`CONTEXT-OPTION` is exactly one of the following value-taking options:

| Option | Accepted forms |
| --- | --- |
| login | `--login VALUE`, `--login=VALUE`, `-l VALUE` |
| repository | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` |
| remote | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` |
| output | `--output VALUE`, `--output=VALUE`, `-o VALUE` |

Each listed option may appear zero or more times, in any order, after the
`logins`/`login` token and before `default`, or after `default`. No context
option is accepted before the top-level token. Every occurrence requires one
value. Long options allow only a separate value or `=` value; short options
allow only a separate value. Short clusters, attached short values, including
`-x=VALUE`, unknown options, and option-like forms in any other position are
outside the grammar.

## Threat model and non-goals

This contract covers normal, non-adversarial use of the pinned Tea CLI. It does
not authenticate the executable, validate option values or Tea configuration,
inspect output, establish Gitea authorization, or constrain data Tea reads. It
does not authorize another executable, direct API use, or an
intentional attempt to bypass the policy.

## Outcomes

An invocation matching every part of this contract is **allowed** as a
read-only default-login inspection. Any route mismatch, positional operand,
unaccepted option, unsupported option form or placement, incomplete option,
assignment, redirect, function, or executable-boundary mismatch **defers** for
normal permission handling. This policy never emits **deny**.
