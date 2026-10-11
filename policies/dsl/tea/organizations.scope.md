# `tea organizations` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

Permit only Tea's default, read-only organization inspection. The protected
asset is remote organization state: `create`/`c`, `delete`/`rm`, and every
other child route remain prompt-gated. The reviewed command definition is
[`cmd/organizations.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/organizations.go)
at Tea commit `bcd62a1`.


## Mandatory accepted grammar

The route is exactly `tea {organizations|organization|org}` with zero
positional operands. The command alias must be the first argument after `tea`;
root-level options before it are not accepted.

After that route, the following routing options may occur in any order, each
zero or more times. Each consumes exactly one value:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

No option is accepted before the route. Long options accept only separate or
`=` values; short options accept only separate values. Attached short values,
short `=` values, short-option clusters, valueless variants, missing values,
and unknown options are not accepted. The invocation must end immediately
after the route or the final option value.

## Threat model and non-goals

This contract covers ordinary, non-adversarial use of the pinned Tea CLI. It
does not establish the executable's provenance beyond the trusted boundary,
prevent intentional use of another executable or direct API client, validate
option values, credentials, identity, remote authorization, response contents,
or command success. It does not authorize organization mutation.

## Outcomes

- **permit:** an exact accepted route at EOF under the trusted execution boundary.
- **defer:** child routes, operands, root options, unknown or malformed options, unsupported option forms, unsafe invocation structure, and target mismatch.
- **deny:** none.
