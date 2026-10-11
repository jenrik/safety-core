# `tea logins status` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits inspection of stored-login authentication status. It protects persisted login configuration and every other login route, including add, edit, delete, default-setting, credential-helper setup, OAuth refresh, and logout.


## Accepted grammar

The route aliases are exactly `tea {logins|login} status`; `status` has no alias. The policy accepts zero or one `LOGIN`, where `LOGIN` is one non-dash argv word. It may appear only after `status`, including after zero or more accepted route-position options; accepted options may also follow it. No root-level option is accepted. A second operand, a dash-prefixed operand, `--` as an option terminator, or any other route token defers.

Each of the following required-value options may occur zero or more times, including with mixed aliases: `--login VALUE` or `--login=VALUE` or `-l VALUE`; `--repo VALUE` or `--repo=VALUE` or `-r VALUE`; `--remote VALUE` or `--remote=VALUE` or `-R VALUE`; and `--output VALUE` or `--output=VALUE` or `-o VALUE`. Each occurrence is accepted after the `logins`/`login` parent, after `status` before the optional `LOGIN`, or after that `LOGIN`. Long options use only separate or `=` values; ordinary short options use only a separate following argv word. Attached short values, `-x=VALUE`, short clusters, unknown options, and missing values defer. The policy records no option cardinality, ordering, or value constraints beyond this grammar.

Tea `bcd62a1` declares `status [<login name>]` and only `--output`/`-o` on `CmdLoginStatus`; no name checks occur until Tea runs. The broader `--login`, `--repo`, and `--remote` admission above is the current policy JSON's generic-option surface, not a claim that upstream `status` accepts or uses those options. A policy allow is therefore not an upstream parsing or execution guarantee.

## Outcomes

Allow only the complete grammar at EOF under the trusted execution assumption. Defer a route or alias mismatch, missing or surplus operand, unknown, malformed, misplaced, or incomplete option, root-level option, assignment, redirect, inherited function, path-qualified Tea, and a non-external-path target. There is no deny outcome.

## Threat model and non-goals

The threat model is ordinary use of a compatible Tea `bcd62a1` CLI, not adversarial attempts to evade recognition through another executable, API client, or shell construction. This policy does not validate login names or option values, inspect stored tokens or status output, establish server-side authorization, guarantee Tea accepts policy-admitted generic options, or change remote or local authentication state.

Sources: [`cmd/login.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/login.go), [`cmd/login/status.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/login/status.go), and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/flags/generic.go).
