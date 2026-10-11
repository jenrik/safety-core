# `tea comments list` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits read-only inspection of comments for one issue or pull request. It protects comment creation, editing, deletion, and the mutating default/add route.


## Accepted grammar

The route is `tea {comments|comment|c} {list|ls} ISSUE_OR_PR`; exactly one non-option index is required. `--repo`/`-r`, `--remote`/`-R`, `--login`/`-l`, and `--output`/`-o` each require one value and may occur after the `comments` parent, after `list`/`ls`, or after the index. `--page`/`-p`, `--limit`, `--lm`, and named alias `-lm` each require one value but may occur only after `list`/`ls` or after the index; pagination is not accepted between the parent and the leaf. Long options allow a separate or `=` value; ordinary short aliases allow only a separate value; named `-lm` allows only `-lm VALUE`. Every option may repeat. Other attached short values and all short clusters are forbidden.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer the default/add route, every mutation route, a missing or surplus index, unknown or misplaced option, malformed value form, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. This policy has no deny outcome.

## Scope limits and non-goals

This scope does not validate the index or option values, prove that the target is an issue versus a pull request, grant write access, or inspect API responses. It assumes normal use of Tea `bcd62a1`, not adversarial workarounds.

Sources: [`cmd/comment.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/comment.go) and [`cmd/comments/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/comments/list.go).
