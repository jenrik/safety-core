# `tea actions runs list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only Actions-run enumeration. It protects run cancellation/deletion and every other Actions mutation.


## Accepted grammar

The route is `tea {actions|action} {runs|run} {list|ls}` with zero operands. Before the intermediate namespace or between that namespace and the leaf, inherited Actions flags allow `--repo VALUE` or `--repo=VALUE`, `--login VALUE` or `--login=VALUE`, and `--output VALUE`, `--output=VALUE`, or `-o VALUE`; each may repeat. After the leaf, leaf generic flags additionally allow `-r VALUE`, `--remote VALUE`, `--remote=VALUE`, `-R VALUE`, and `-l VALUE`. After the leaf only, `--page`/`-p`, `--status`, `--branch`, `--event`, `--actor`, `--since`, and `--until` each require one value; `--limit`, `--lm`, and named `-lm` are one-value aliases there. Each accepted option may repeat. Attached short values and short clusters are forbidden, except named `-lm` as the separate-value alias.

## Outcomes

Allow only that grammar at EOF under the trusted execution assumption. Defer operands, root options, leaf-only options before the leaf, unknown option, malformed value, run mutation route, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. No deny branch exists.

## Scope limits and non-goals

It does not change Actions runs, validate filter values or results, or establish server authorization. The threat model is ordinary Tea `bcd62a1` use, not adversarial evasion.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/runs.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/runs.go), and [`cmd/actions/runs/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/runs/list.go).
