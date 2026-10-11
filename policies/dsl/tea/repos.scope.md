# `tea repos` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

`repos.policy.json` permits Tea's read-only repository parent behavior. At Tea
commit `bcd62a1`, `tea repos` dispatches to `RunReposList`; one repository
operand dispatches to repository detail. The protected assets are remote
repository state and configuration: creation, template creation, forking,
migration, deletion, and editing remain outside this policy.

## Accepted grammar

The complete permitted grammar is:

```text
tea {repos|repo} OPTION* [REPOSITORY OPTION*]
```

`REPOSITORY` is one non-dash shell word, is optional, and has cardinality zero
or one. With no operand, Tea runs the default repository listing; with one, it
reads that repository's details. Accepted options may occur zero or more times,
in any order, before or after the optional operand. They are the exact parent
`CmdReposListFlags` declared at the pinned commit:

- Watched: `--watched` or `-w` (no value).
- Starred: `--starred` or `-s` (no value).
- Owner: `--owner VALUE`, `--owner=VALUE`, or `-O VALUE`.
- Fields: `--fields VALUE`, `--fields=VALUE`, or `-f VALUE`.
- Type: `--type VALUE`, `--type=VALUE`, or `-T VALUE`.
- Page: `--page VALUE`, `--page=VALUE`, or `-p VALUE`.
- Limit: `--limit VALUE`, `--limit=VALUE`, `--lm VALUE`, `--lm=VALUE`, or
  named alias `-lm VALUE`.
- Login: `--login VALUE`, `--login=VALUE`, or `-l VALUE`.
- Output: `--output VALUE`, `--output=VALUE`, or `-o VALUE`.

The policy does not validate required option values or impose a per-option
cardinality limit. Long required-value options accept only separate-value and
`=` forms. Ordinary short required-value aliases accept only separate-value
forms. `-lm` is an explicit two-character alias and accepts only `-lm VALUE`.
Root-level options, `--watched=VALUE`/`--starred=VALUE`, short-option clusters,
attached short values, and `-x=VALUE` forms are not part of the grammar. A bare
word after watched or starred is the optional repository operand, not a flag
value.

`list`/`ls` and `search`/`s` are child routes, not optional spellings of this
parent action. The mutating child aliases `{create|c}`, `{create-from-template|ct}`,
`{fork|f}`, `{migrate|m}`, `{delete|rm}`, and `{edit|e}` likewise are not
accepted here. `--repo`/`-r` and `--remote`/`-R` are not parent listing flags
at this commit and defer rather than routing the invocation.

## Outcomes

- **allow:** a complete accepted grammar at EOF within the trusted execution boundary.
- **defer:** a child route, second repository operand, unknown or malformed
  option, missing option value, unsupported option form or placement, unsafe
  invocation form, or executable-target mismatch.
- **deny:** none.

## Threat model and non-goals

This policy permits normal, non-adversarial use modeled after Tea `bcd62a1`.
It neither validates repository, option values,
credentials, context, responses, success, or server-side authorization. It
does not authorize repository mutation or provide assurance for executable
replacement or alternate API clients.

Sources: [`cmd/repos.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos.go), [`cmd/repos/list.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/repos/list.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
