# Redirect input fixture scope

## Intent and protected asset

Exercise immutable effective stdin evidence and separate harness file
authorization through the packaged CLI. This is a test fixture, not a production
kubectl or general command permission. It protects the automatic authorization
boundary from hidden redirects or unproved input.

## In scope

Only the synthetic executable basename `redirect-fixture` is selected. Arguments
are immaterial to this synthetic command. Literal and binding-expanded
here-strings, effective file stdin, standalone output redirects, and compound
redirect inheritance are within the analyzer regression scope. Every shell-owned
file open remains subject to separate harness authorization.

## Expected decisions

- **Permit** (`allow`): `redirect-fixture <<<"accepted"`; no user-file access.
- **Defer**: `redirect-fixture <<<"different"`, unknown inline content, or
  inherited stdin; none proves accepted input.
- **Defer**: `> output; redirect-fixture <<<"accepted"`; command input is
  accepted, but the standalone file modification needs harness permission.
- **Defer offline**: `redirect-fixture <<<"accepted" > /dev/null`; `/dev/null`
  has no exemption and its modification needs harness permission.
- **Defer offline**: `redirect-fixture < /review/trusted.yaml`; the command
  condition passes, but the CLI has no harness read-permission checker.
  A live checker allowing every required file access can permit it.
- **Deny**: `redirect-fixture <<<"forbidden"`, including with output redirects.
  A harness file allow must not override command denial.
- **Defer**: parser failures and unsupported redirect semantics, unless a
  independently established denial dominates.

## Assumptions, non-goals, and exclusions

The fixture executable is never run during validation or explanation. Trust in
`/review/trusted.yaml` is synthetic path trust; contents are neither read nor
verified. It is not a guarantee against concurrent filesystem changes. File
accesses encoded in argv/configuration and policy-emitted file/directory lists
are out of scope. Pipes and process substitutions need both command invocations
covered, but do not create harness file-access requests themselves. General
filesystem mediation, shell execution, and adversarial bypasses are excluded;
the threat model concerns natural tool use and supported equivalent spellings.

Explicit descriptor-zero forms are a known unresolved parser bug, documented
as "Description-zero parsing" in `docs/known-bugs.md`. Their executable/argv
projection is not a reliable proof; this fixture does not claim that bug is
fixed by the redirect authorization work.
