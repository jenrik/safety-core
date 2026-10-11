# `tea branches` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This policy permits Tea's read-only `RunBranchesList` parent action. At Tea
commit `bcd62a1`, the parent command lists branches and their protection
information with zero operands, or shows one branch's details with one branch
name. The protected assets are branch names and branch protection state. The
policy does not permit child actions that protect, unprotect, or rename a
branch.

The authoritative upstream definitions are
[`cmd/branches.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/branches.go),
[`cmd/branches/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/branches/list.go),
and
[`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).


## Accepted grammar

The only command-route tokens accepted by this policy are `branches`,
`branch`, and `b`. After exactly one of those tokens, zero or more of the
following options may occur in any order before or after an optional single
branch-name operand. The command must then end:

| Option names | Required value | Accepted forms | Placement | Cardinality |
| --- | --- | --- | --- | --- |
| `--comments` | optional boolean value | `--comments`, `--comments=VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--fields`, `-f` | one opaque argv word | `--fields VALUE`, `--fields=VALUE`, `-f VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--page`, `-p` | one opaque argv word | `--page VALUE`, `--page=VALUE`, `-p VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--limit`, `--lm`, `-lm` | one opaque argv word | `--limit VALUE`, `--limit=VALUE`, `--lm VALUE`, `--lm=VALUE`, `-lm VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--login`, `-l` | one opaque argv word | `--login VALUE`, `--login=VALUE`, `-l VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--repo`, `-r` | one opaque argv word | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--remote`, `-R` | one opaque argv word | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` | after the parent alias, before or after the branch name | zero or more |
| `--output`, `-o` | one opaque argv word | `--output VALUE`, `--output=VALUE`, `-o VALUE` | after the parent alias, before or after the branch name | zero or more |

`VALUE` has no value-domain validation in this policy. A separate required
value is the next argv word, including a word that looks like an option or a
route token. An equals-long value may be empty; for example, `--login=` and
`--comments=` are permitted syntactic forms. Bare `--comments` does not consume
a following word, so `--comments topic` is the bare flag and the one permitted
branch-name operand, not a separated comments value. The policy records no
option-use state, so every listed option may be repeated without a
policy-level upper bound. The optional branch name is one non-dashed opaque
argv word.

The policy accepts neither root-level options nor options after a child route,
because options are available only after the parent alias and around its
optional detail operand. It accepts no second positional operand. It accepts
no other Tea branch options.

Only the forms listed in the table are accepted. In particular, this policy
does not accept attached short values (`-lVALUE` or `-l=VALUE`), short-option
clusters (`-lr`), a bare value-taking option at EOF, or an equals form for a
short option. `-lm` is a named alias, not a cluster, and only accepts its value
as the next argv word. The parser does not special-case `--`; it is an ordinary
argv word, so it can only be consumed as the separate value of a preceding
required option and is otherwise deferred.

## Decision contract

- **permit:** At EOF, permit exactly the accepted grammar above, only under the
  trusted execution assumption. In the policy document this is the `allow`
  action.
- **defer:** Defer every other selected `tea` invocation: missing or different
  route token; `list`/`ls`, `protect`/`P`, `unprotect`/`U`, or `rename`/`rn`;
  a second positional operand; an undeclared,
  malformed, or misplaced option; an unsupported option form; a missing
  required value; or a failed trusted-execution condition. Root-level options
  also defer. Commands whose executable does not select this policy receive no
  decision from this policy rather than an allow.
- **deny:** This policy contains no deny action.

## Exclusions, threat model, and non-goals

The contract is limited to ordinary use of a compatible Tea `bcd62a1` CLI. It
does not establish the executable's identity beyond the trusted-execution
assumption, authenticate the user, authorize the remote request, validate
option values, validate repository or login selection, inspect output, or
prove API success. It does not authorize direct API clients or other command
names. Deliberate replacement of `tea` or deliberate use of an alternative
client to evade this route policy is outside the non-adversarial threat model.
