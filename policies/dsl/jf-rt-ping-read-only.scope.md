# `jf-rt-ping-read-only` policy scope

## Intent

Permit the JFrog CLI's Artifactory applicative health check without a harness
prompt. The policy is deliberately limited to the documented `jf rt ping`
operation and its documented `p` subcommand alias in JFrog CLI 2.124.0.

## Protected action and asset

The protected action is an authenticated request to the default configured
Artifactory server's applicative ping endpoint. The policy protects remote
Artifactory administration from a different `jf rt` action, protects local
files from command-summary output and alternate CLI-home reads, and prevents
automatic use of caller-supplied credentials or target-selection inputs.

## In scope

The policy permits only a complete modeled invocation with all of these
properties:

- The executable is the direct, unqualified `jf` spelling; it is not
  path-qualified and is not shadowed by an inherited executable function.
- The command path is exactly `jf rt ping` or `jf rt p`. `p` is the documented
  alias for `ping`.
- After the `ping`/`p` word, zero or more `--format` options may appear. Each
  value is exactly `json` or `table`; both `--format VALUE` and
  `--format=VALUE` are accepted. Repeated valid format options are accepted,
  since each is a documented output-only option.
- There are no command-prefix assignments or redirections.
- `JFROG_CLI_COMMAND_SUMMARY_OUTPUT_DIR`, `JFROG_CLI_ENCRYPTION_KEY`,
  `JFROG_CLI_HOME_DIR`, and `JFROG_CLI_SERVER_ID` are absent or have known
  empty values. `CI`, standard logging settings, and the normal default JFrog
  CLI configuration are not constrained by this policy.

Examples of equivalent in-scope forms are:

```sh
jf rt ping
jf rt p
jf rt ping --format json
jf rt p --format=table
jf rt ping --format table --format=json
```

## Out of scope and threat-model exclusions

Every other `jf` command path and every other executable spelling, including
`jfrog`, defer. This policy does not cover root/global help, `jf rt` help,
`ping --help`, or a path-qualified `jf`; command-discovery policy is separate.

All connection, credential, and transport-affecting options defer, including
`--access-token`, `--client-cert-key-path`, `--client-cert-path`,
`--insecure-tls`, `--password`, `--server-id`, `--ssh-key-path`,
`--ssh-passphrase`, `--url`, and `--user`. `--format` has no short form in the
reviewed CLI help, so `-f`, attached short forms, and option clusters defer.
Unknown, missing, unresolved, empty, or case-variant format values defer, as
do `--`, extra operands, options before `ping`/`p`, repeated invalid values,
and incomplete command paths.

This policy evaluates the modeled `jf` invocation. It does not independently
authorize an outer shell wrapper or another command in a pipeline; those events
must be covered by their own policies. Attempts to use another executable,
direct HTTP client, alias/function manipulation, or a custom transport to
bypass the scope are outside the non-adversarial threat model.

## Assumptions and non-goals

JFrog CLI 2.124.0 documents `jf rt ping` as an applicative Artifactory ping and
documents `json` and `table` as its only output formats. The policy assumes
that this server request does not mutate Artifactory business or administrative
state. Normal server access logging, existing configured-credential use, and
JFrog CLI implementation behavior outside the modeled invocation are not
proved by this policy.

The policy binds only the direct unqualified executable spelling `jf`; it does
not bind a selected path, canonical target, package hash, or runtime version.
The operator accepts this risk and must ensure that `jf` resolves through a
trusted `PATH` to the reviewed JFrog CLI 2.124.0 implementation. A different
program named `jf` is outside this policy's authorization proof.

`JFROG_CLI_COMMAND_SUMMARY_OUTPUT_DIR` is excluded because JFrog CLI documents
that it writes per-command summary directories. `JFROG_CLI_HOME_DIR` and
`JFROG_CLI_SERVER_ID` are excluded to retain the default configured target and
avoid selecting an alternate local configuration; `JFROG_CLI_ENCRYPTION_KEY` is
excluded because it is sensitive configuration input. This policy does not
allow repository, permission, project, user, group, worker, configuration,
token, or general API inspection; those require separate scopes.

Two core-modeling limitations are explicitly out of scope and recorded in
[`docs/known-bugs.md`](../../docs/known-bugs.md): complete environment snapshots
do not normalize exported Bash functions, and here-strings are not projected as
redirects. Thus the inherited-function and redirect checks apply only to facts
carried by the modeled invocation event; they do not prove that an exported
`jf` function cannot shadow the executable or that a source has no here-string.

## Expected outcomes

- **permit:** exactly the in-scope `jf rt ping` or `jf rt p` forms yield
  `allow` from this permission policy.
- **defer:** every incomplete, malformed, unknown, excluded, unsafe-environment,
  *modeled* redirected, assigned, path-qualified, or *modeled*
  function-shadowed form yields `defer` and remains prompt-gated unless another
  independent policy covers it. The two documented core-modeling limitations
  above are explicit exceptions to this proof.
- **deny:** this permission policy contains no deny rule. A guard policy can
  still deny the full request; that dominant decision is outside this policy's
  ping authorization.
