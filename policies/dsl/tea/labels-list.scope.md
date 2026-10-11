# `tea labels list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This policy grants only label enumeration. It protects remote label state and every
local path that Tea's `LabelsExport` can create or truncate when `--save`/`-s` is
used. It does not grant a local label-export write.


## Accepted grammar

The complete route is `tea {labels|label} {list|ls}` with no operands. The
top-level aliases are exactly `labels` and `label`; the leaf aliases are exactly
`list` and `ls`. Root options before `labels`/`label` are not accepted.

Each non-save option may occur zero or more times, in any order, either after
`labels`/`label` and before `list`/`ls`, or after `list`/`ls`:

- `--org VALUE`
- `--exclude-org`
- `--page VALUE` or `-p VALUE`
- `--limit VALUE`, `--lm VALUE`, or `-lm VALUE`
- `--login VALUE` or `-l VALUE`
- `--repo VALUE` or `-r VALUE`
- `--remote VALUE` or `-R VALUE`
- `--output VALUE` or `-o VALUE`

Every long option requiring a value also accepts the exact `--name=VALUE` form.
Every short option requires a separate value. In particular, `-lm` is a named
alias, not a short-option cluster, and requires a separate value. Valueless
`--exclude-org` accepts no value. No other aliases, options, operands, or option
placements are in the grammar.

`--save` and `-s` are recognized, valueless options at either of those two
post-top-level positions and may repeat, but their presence always excludes the
command from allow. They are modeled only so the policy can detect and defer Tea's
export behavior.

## Pinned Tea behavior

At commit `bcd62a1`, Tea declares the route and aliases in
[`cmd/labels.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/labels.go)
and [`cmd/labels/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/labels/list.go).
The latter has no positional arguments, defines `--save`/`-s`, `--org`,
`--exclude-org`, pagination, and Tea's shared default flags. `--save` invokes
[`LabelsExport`](https://gitea.com/gitea/tea/src/commit/bcd62a1/modules/task/labels_export.go),
which uses `os.Create`; this is the reason every save form remains prompt-gated.

## Threat model and non-goals

The policy applies to normal, non-adversarial use of a compatible pinned Tea CLI.
It does not establish server authorization, validate option values, repository or
organization context, credentials, output, returned labels, or Tea command
success. Other executable spellings and deliberate substitution of another client
are outside this policy's assurance and are governed by other permission handling.

## Outcomes

Allow occurs only at end of arguments for the accepted non-save grammar under the
trusted execution assumption. Missing values, values on valueless options, unknown
or misplaced options, short clusters, attached short values, unsupported
`-x=VALUE` forms, bare operands, route mismatches, save options, direct Tea
assignments or redirections, inherited functions, and failed direct/external target
checks defer.
This policy never denies.
