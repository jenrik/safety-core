# `tea actions workflows view` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

Permit workflow detail inspection without authorizing dispatch or enablement
changes. Source: Tea `bcd62a1`, `cmd/actions/workflows.go` and
`cmd/actions/workflows/view.go`.

## Precise forms

The route is `tea {actions|action} {workflows|workflow} {view|show|get} WORKFLOW_ID`. Before the namespace or between the namespace and leaf, inherited Actions flags permit only `--repo`, `--login`, and `--output` (with `-o`), each with one value and with `=` allowed on long forms. Between the leaf and `WORKFLOW_ID`, or after the ID, leaf generic flags additionally permit `-r`, `--remote`/`-R`, and `-l`. Unsupported short attachment and clustering defer.

## Exclusions and threat model

Other or incomplete routes, a path-qualified spelling, assignments,
redirections, inherited functions, and an execution target other than
`external-path` defer. Tea
replacement or alternate clients are outside the non-adversarial threat model.

## Assumptions and non-goals

`runWorkflowsView` only gets and prints a workflow at the reviewed commit.
Flag semantics, credentials, output sensitivity, and API success are non-goals.

## Outcomes

- **permit:** exact route aliases with one ID and only the documented generic routing flags at EOF.
- **defer:** missing or extra operands, unknown flags, and every other form, including a path-qualified spelling or execution target other than `external-path`.
- **deny:** none.
