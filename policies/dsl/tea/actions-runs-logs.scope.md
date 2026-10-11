# `tea actions runs logs` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

Permit workflow-run log inspection without authorizing workflow-run changes.
The protected asset includes remote execution state; log disclosure is an
operator-accepted consequence of this read-only route. Source: Tea `bcd62a1`,
`cmd/actions/runs.go` and `cmd/actions/runs/logs.go`.

## Precise forms

The route is `tea {actions|action} {runs|run} {logs|log} RUN_ID`. Before the namespace or between the namespace and leaf, inherited Actions flags permit only `--repo`, `--login`, and `--output` (with `-o`), each with one value and with `=` allowed on long forms. Between the leaf and `RUN_ID`, or after the ID, leaf generic flags additionally permit `-r`, `--remote`/`-R`, and `-l`. Unsupported short attachment and clustering defer.

## Exclusions and threat model

Other or incomplete routes, a path-qualified spelling, assignments,
redirections, inherited functions, and an execution target other than
`external-path` defer. Tea
replacement or alternate clients are outside the non-adversarial threat model.

## Assumptions and non-goals

`runRunsLogs` does not mutate the server at the reviewed commit. It does not
redact logs, validate flags, credentials, output handling, or API success.

## Outcomes

- **permit:** exact route aliases with one ID and only the documented generic routing flags at EOF.
- **defer:** missing or extra operands, unknown flags, and every other form, including a path-qualified spelling or execution target other than `external-path`.
- **deny:** none.
