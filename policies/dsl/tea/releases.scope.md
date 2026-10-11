# Tea Releases Parent Policy Contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

This is the mandatory scope contract for `releases.policy.json`.

## Intent and protected assets

The policy permits only Tea's default, parent-level release listing action. At Tea
`bcd62a1`, that action is `releases.RunReleasesList`; the command accepts no
positional arguments and is registered with the default repository-routing flags.
It protects remote release records and release assets from creation, deletion,
editing, upload, and deletion. Sources: [`cmd/releases.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/releases.go) and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).

## Exact accepted command language

The route is exactly:

```text
tea {releases|release|r} [PARENT-FLAG ...]
```

`[PARENT-FLAG ...]` has zero-or-more cardinality. Each of the following flags
may appear zero or more times, in any order, only after the route token and
before end of arguments:

| Flag | Required value | Accepted forms |
| --- | --- | --- |
| `--login`, `-l` | one value | `--login VALUE`, `--login=VALUE`, `-l VALUE` |
| `--repo`, `-r` | one value | `--repo VALUE`, `--repo=VALUE`, `-r VALUE` |
| `--remote`, `-R` | one value | `--remote VALUE`, `--remote=VALUE`, `-R VALUE` |
| `--output`, `-o` | one value | `--output VALUE`, `--output=VALUE`, `-o VALUE` |

The policy intentionally imposes no value-domain, ordering, or per-flag
cardinality constraint beyond the required value and parent-only placement.
These four flags are Tea's `AllDefaultFlags` at the pinned revision.

Root-level options before `{releases|release|r}` are not part of this contract
and MUST defer. The policy accepts neither short-option clusters nor attached
short values: `-lr`, `-lVALUE`, and `-l=VALUE` MUST defer. The DSL cannot
represent `-l=VALUE` without also accepting unsupported `-lVALUE`, so both are
excluded. No other flag form or positional operand is accepted.

## Route exclusions

The parent policy MUST defer if another route token follows the parent route,
including `list`/`ls`, `create`/`c`, `delete`/`rm`, `edit`/`e`, and
`assets`/`asset`/`a`. This policy therefore cannot authorize release mutation or
asset mutation; separately scoped policies may authorize read-only child routes.
Unknown dash-prefixed words and every non-route token other than a required flag
value MUST also defer.

## Threat model and non-goals

The threat model covers natural agent use of a trusted, compatible Tea CLI. It
does not cover a malicious executable replacement, incompatible Tea parser
behavior, alternate API clients, or deliberate evasion through another command.

The policy does not validate flag values, repository selection, configured login,
credentials, remote authorization, server-side authorization, returned release
data, output safety, or Tea/API success. Tea and Gitea remain responsible for
those validations and effects.

## Outcomes

| Outcome | Required behavior |
| --- | --- |
| `allow` | A complete accepted command reaches end of arguments and has the required direct external target shape, with no assignments, redirects, or inherited `tea` function. The rationale is `tea releases is read-only`. |
| `defer` | Every target mismatch, incomplete flag, unsupported form, root-level flag, child route, positional operand, unknown flag, or other non-matching invocation defers for normal permission handling. |
| `deny` | This policy never denies. |
