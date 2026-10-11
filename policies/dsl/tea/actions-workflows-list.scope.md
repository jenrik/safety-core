# `tea actions workflows list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only workflow enumeration. It protects workflow dispatch, enablement, disablement, and all other Actions mutations.


## Accepted grammar

The route is `tea {actions|action} {workflows|workflow} {list|ls}` with zero operands. Before `workflows`/`workflow` or between that namespace and `list`/`ls`, inherited Actions flags allow `--repo VALUE` or `--repo=VALUE`, `--login VALUE` or `--login=VALUE`, and `--output VALUE`, `--output=VALUE`, or `-o VALUE`; each may repeat. After the leaf, leaf generic flags additionally allow `-r VALUE`, `--remote VALUE`, `--remote=VALUE`, `-R VALUE`, and `-l VALUE`. Every accepted option consumes one value. Neither attached short values nor short-option clusters are accepted.

## Outcomes

Allow only the grammar at EOF under the trusted execution assumption. Defer operands, root options, leaf-only options before the leaf, unknown option, malformed value form, workflow mutations, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This scope never denies.

## Scope limits and non-goals

It does not dispatch or change workflows, validate repository or login values, inspect results, or grant remote authorization. It models normal use of the pinned CLI, not adversarial policy bypass.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/workflows.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/workflows.go), and [`cmd/actions/workflows/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/workflows/list.go).
