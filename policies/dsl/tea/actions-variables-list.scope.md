# `tea actions variables list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only Actions-variable enumeration. It protects variable creation, update, deletion, and all other Actions mutations.


## Accepted grammar

The route is `tea {actions|action} {variables|variable|vars|var} {list|ls}` with zero operands. Before the intermediate namespace or between that namespace and the leaf, inherited Actions flags allow `--repo VALUE` or `--repo=VALUE`, `--login VALUE` or `--login=VALUE`, and `--output VALUE`, `--output=VALUE`, or `-o VALUE`; each may repeat. After the leaf, leaf generic flags additionally allow `-r VALUE`, `--remote VALUE`, `--remote=VALUE`, `-R VALUE`, and `-l VALUE`. After the leaf only, `--name` permits `--name VALUE` or `--name=VALUE`. Attached short values and every short cluster defer.

## Outcomes

Allow only that grammar at EOF under the trusted execution assumption. Defer operands, root options, leaf-only options before the leaf, unknown option, malformed value form, variable mutation routes, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. There is no deny branch.

## Scope limits and non-goals

The scope does not reveal variable values, change variables, validate filters or selectors, inspect responses, or establish remote authorization. It covers normal Tea `bcd62a1` usage only.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/variables.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/variables.go), and [`cmd/actions/variables/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/variables/list.go).
