# `tea actions secrets` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This policy permits only Tea's default `actions secrets` listing route. It
protects repository Actions-secret state from creation, replacement, and
deletion. At pinned commit `bcd62a1`, its parent default dispatches to the
read-only secret listing.


## Accepted grammar

The only route words are `tea {actions|action} {secrets|secret}`. There are no
operands, child-route words, or root-level options. The three inherited Actions
options below are accepted zero or more times, in any order, after
`actions`/`action` and before `secrets`/`secret`, and again zero or more times,
in any order, after `secrets`/`secret` through EOF:

- `--login VALUE` or `--login=VALUE`
- `--repo VALUE` or `--repo=VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Every occurrence requires exactly one value. A separate value is the next argv
word, including a word beginning with `-` or the literal `--`; an equals-long
form accepts the entire suffix after `=`, including an empty suffix. The policy
does not constrain option values or impose a repetition limit. Long options
accept only the listed separate and equals-long forms; `-o` accepts only its
listed separate form. `-l`, `-r`, `--remote`, and `-R` are not inherited Actions
options. Attached short values such as `-ojson` and `-o=json`, and every short
option cluster, are not accepted.

## Explicit outcomes

- **permit:** The accepted grammar is complete at EOF and the trusted-execution
  assumption holds. The policy audits the original invocation.
- **defer:** Every other invocation, including root-level options; an operand;
  an unknown, misplaced, or valueless option; an attached short value or short
  cluster; a standalone `--`; and any child route. Child names `list`, `ls`,
  `create`, `add`, `set`, `delete`, `remove`, and `rm` defer, as does every
  other child word. Invocations outside the trusted-execution assumption also
  defer.
- **deny:** None.

## Exclusions, threat model, and non-goals

The contract does not permit a secret mutation, authorize a server request,
validate repository selection or option values, inspect response data, or prove
that server output is safe. It relies on the compatible Tea default route not
returning secret values; it does not prove remote implementation or permission
semantics. The threat model is ordinary use of compatible Tea `bcd62a1`, not
adversarial substitution of Tea or use of another API client to evade policy.

Sources: [`cmd/actions.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions.go), [`cmd/actions/secrets.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/secrets.go), and [`cmd/actions/secrets/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/actions/secrets/list.go).
