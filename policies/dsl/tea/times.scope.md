# `tea times` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy permits only Tea's default read-only tracked-time listing action.
The protected asset is remote repository time-tracking data, especially time
entry creation, deletion, and reset; those operations and every other route
remain prompt-gated.

At pinned Tea commit `bcd62a1`, the parent command's action is
`times.RunTimesList`; `add`, `delete`, `reset`, and `list` are child commands.
The compatible parent route therefore inspects tracked-time data without
selecting a child operation.


## Exact accepted grammar

The complete accepted invocation grammar is:

```text
tea {times|time|t} [OPTION...]
```

The parent-route aliases are exactly `times`, `time`, and `t`, each appearing
once as the first argument after `tea`. No root-level option is accepted before
that alias.

After the parent alias, the policy accepts `--login`/`-l`, `--repo`/`-r`,
`--remote`/`-R`, and `--output`/`-o`. Each requires one value and may occur
zero or more times, including repeated or mixed aliases, in any order. Long
forms are `--long VALUE` and `--long=VALUE`; ordinary short forms are only
`-x VALUE`. Root-level options, missing values, `-x=VALUE`, attached short
values, and short clusters defer.

No positional operand is allowed. The child-route tokens `add`, `a`, `delete`,
`rm`, `reset`, `list`, and `ls` are explicitly outside this policy and defer.

## Threat model and non-goals

This is a non-adversarial policy for normal use of the Tea CLI. Deliberate
binary replacement, use of another API client, or attempts to bypass a deferred
invocation are outside its assurance boundary.

The policy does not validate repository selection, credentials, remote
authorization, output handling, returned time data, or upstream API success.
It does not establish that the reviewed action remains read-only in a different
Tea version.

## Outcomes

- **allow:** only the accepted grammar at argv EOF with the trusted execution shape.
- **defer:** every other invocation, including root-level or malformed options, operands, child routes, unknown tokens, direct Tea assignments or redirects, inherited functions, path-qualified Tea, and a non-external-path target.
- **deny:** none.

Sources: [`cmd/times.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/times.go) and [`cmd/times/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/times/list.go).
