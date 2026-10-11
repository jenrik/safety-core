# `tea pulls list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy permits only explicit, read-only pull-request enumeration. It
protects pull-request state, including creation, editing, review, approval,
rejection, closing, reopening, merging, comment/review mutation, and every
other non-list pull route. Although Tea's parent `pulls` action lists pull
requests when invoked without an argument, this policy MUST NOT authorize that
implicit parent action; an explicit `list` or `ls` leaf is required.

Sources: [`cmd/pulls.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/pulls.go),
[`cmd/pulls/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/pulls/list.go),
and Tea's shared listing and context flags at commit `bcd62a1`.


## Accepted grammar

The complete permitted argv grammar is:

```text
tea {pulls|pull|pr} PULLS_OPTION* {list|ls} LIST_OPTION*
```

The command MUST end immediately after the final `LIST_OPTION`; no positional
operand is accepted. `PULLS_OPTION` is accepted only after `{pulls|pull|pr}`
and before `{list|ls}`. `LIST_OPTION` is accepted only after `{list|ls}`.
Options listed for both positions may be interleaved in either position, but
the route words remain mandatory and ordered.

| Option | Accepted spellings | Accepted forms | Accepted placement | Cardinality |
| --- | --- | --- | --- | --- |
| comments | `--comments` | `--comments` | `PULLS_OPTION` only | zero or more |
| fields | `--fields`, `-f` | `--fields VALUE`, `--fields=VALUE`, `-f VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| state | `--state` | `--state VALUE`, `--state=VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| page | `--page`, `-p` | `--page VALUE`, `--page=VALUE`, `-p VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| limit | `--limit`, `--lm`, `-lm` | `--limit VALUE`, `--limit=VALUE`, `--lm VALUE`, `--lm=VALUE`, `-lm VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| login | `--login`, `-l` | `--login VALUE`, `--login=VALUE`, `-l VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| repo | `--repo`, `-r` | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| remote | `--remote`, `-R` | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |
| output | `--output`, `-o` | `--output VALUE`, `--output=VALUE`, `-o VALUE` | `PULLS_OPTION`, `LIST_OPTION` | zero or more |

Every required value is exactly one argv word. The policy does not validate its
meaning, including whether it begins with `-`; `--` is not a general option
terminator and is accepted only when consumed as a separate required value.
`--comments` takes no value. Only long options accept `=VALUE`. Ordinary short
aliases accept only a separate value. `-lm` is an explicit named limit alias,
not a short cluster, and accepts only `-lm VALUE`. Attached short values,
including `-fVALUE` and `-f=VALUE`, all short clusters, and a value attached to
`--comments` MUST defer. Root-level options before `{pulls|pull|pr}` MUST defer.

## Explicit outcomes

- **permit:** An invocation matching the complete grammar at argv EOF, with the trusted execution assumptions satisfied. This includes every route alias, every tabled option spelling, and only the listed forms, placements, and cardinalities.
- **defer:** Every non-permitted form. This includes the bare parent action; missing route words or option values; any operand; root-level, unknown, malformed, attached-short, clustered, or misplaced option; `--comments` after the leaf or with a value; every sibling or child pull route; a path-qualified or non-external target; an assignment; a redirection; and an inherited `tea` function.
- **deny:** No invocation is denied by this policy.

## Threat model and non-goals

This is a permission recognizer, not authorization for repository access. It
does not validate option values, repository selection, credentials, server
permissions, returned pull-request data, output handling, or API success. It
does not inspect alternate CLIs, direct HTTP/API calls, or
attempts to evade recognition. The threat model is ordinary use of a
Tea-compatible external `tea` at commit `bcd62a1`, not adversarial substitution
or bypass.
