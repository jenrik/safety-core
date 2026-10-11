# `tea logins helper` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This policy auto-permits only invocation of Tea's credential-helper parent command. It protects Git credential-helper configuration, Tea's persisted login configuration and access tokens, and credential-protocol input and output from an automatic grant. The permitted parent invocation has no child action; at pinned Tea `bcd62a1`, the potentially consequential children are `setup` (writes Git configuration) and `get` (reads stdin, may refresh an OAuth token, and writes a token to stdout).


## Accepted grammar

The complete route is `tea {logins|login} [LOGIN-FLAG ...] {helper|git-credential} [PARENT-FLAG ...]`. `logins` and `login` are the only accepted top-level aliases; `helper` and `git-credential` are the only accepted helper aliases. The route has zero positional operands and no child command.

`LOGIN-FLAG` is accepted only after `logins`/`login` and before `helper`/`git-credential`; `PARENT-FLAG` is accepted only after the helper alias. At either allowed placement, each option may occur zero or more times, in any order with the other options at that placement:

- `--login VALUE`, `--login=VALUE`, or `-l VALUE`
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`

Every occurrence requires exactly one argv value. The policy imposes no uniqueness, maximum-occurrence, value-content, or relationship constraint; a separate value is consumed even when it begins with `-` or is `--`. Options are not accepted before `logins`/`login`, between an option and its required value, or after any other route word. Long options allow only separate and `=` forms; short options allow only separate forms. Attached short values, `-x=VALUE`, and short clusters defer.

## Deferred routes and forms

The exact helper child words `store`, `erase`, `setup`, and `get` defer, as does every other trailing argv word, option spelling, malformed option/value pair, or route mismatch. `store`/`erase` are Tea's no-op credential-protocol child; their separate policy owns that route. `setup` registers Tea as a Git credential helper, and `get` can return or refresh a stored token; neither is auto-permitted here. Root-level options before the top-level command also defer.

## Outcomes

Allow only when the accepted route and permitted option grammar reach EOF under the trusted execution assumption. All other invocations defer to the native permission system. This policy has no deny branch.

## Threat model and non-goals

The threat model is ordinary use of a Tea `bcd62a1`-compatible external binary, not adversarial policy evasion or replacement of `tea` with another program. This contract does not parse or validate credential-protocol stdin, option values, Tea configuration, Git configuration, tokens, server authorization, or command output. It does not grant permission to configure Git credentials, retrieve or refresh credentials, mutate login data, or execute any helper child.
