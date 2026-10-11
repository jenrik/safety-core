# `tea open` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent

Recognize Tea's exact `open` route and its `o` alias so an attempted browser or
URL launch is explicitly deferred rather than being mistaken for a strictly
read-only repository inspection.

## Protected action and asset

The protected action is automatic authorization of a selected `tea` invocation.
The protected asset is the user's browser and desktop URL-opening boundary:
`tea open` delegates a repository URL to an external opener. This policy does
not treat launching that opener as a read-only operation.

## In scope

The permission policy selects only modeled invocation events whose executable
basename is exact, case-sensitive `tea`. It recognizes only the first argument
routes `open` and `o`. Either route immediately returns `defer`, before parsing
any later flags or operands, so `tea open`, `tea o`, and every variant with
arguments are never automatically permitted by this policy.

Every other first argument, an argument-less `tea` invocation, and a basename
other than exact lowercase `tea` defer immediately. This keeps route selection
exact and leaves unrelated Tea command paths to their individual policies.

## Assumptions and non-goals

The policy assumes upstream Tea retains `open` with alias `o` as the helper that
opens a repository resource in a web browser. It does not establish executable
identity, validate Tea's URL selection, inspect a browser or URL-opener
configuration, or determine whether the opener succeeds.

This is not a browser sandbox, URL allowlist, network-access policy, or a
permission policy for other Tea commands. Prefix assignments, redirections,
functions, aliases, pipelines, nested shell constructs, and separate modeled
commands receive their own harness and policy decisions; none can turn this
route into an automatic permit.

Deliberately bypassing this policy through another executable or a bespoke URL
opener is outside the non-adversarial agent threat model.

## Expected outcomes

- **permit:** none. `tea open`/`tea o` has no automatically permitted form.
- **defer:** exact `open`/`o` routes defer with the full invocation audit. The
  DSL does not support a reason on a defer terminal; this scope records that the
  route launches a browser or URL opener. Empty, unsupported, or unrelated
  routes also defer, without authorizing any other Tea path.
- **deny:** this permission policy has no deny rule. A separate guard policy may
  deny the invocation, and such a decision dominates a defer from this policy.

## Upstream source

Tea's command inventory identifies `open, o` as opening a repository resource
in a web browser: <https://gitea.com/gitea/tea/commit/bcd62a1>.
