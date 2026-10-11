# `tea whoami` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected boundary

This scope permits inspection of the currently authenticated Gitea user. It protects all remote Gitea mutation and every Tea route other than `whoami`.


## Accepted grammar

The complete route is `tea whoami`; it has no aliases and accepts zero positional operands. Only after `whoami`, each of the following options may occur zero or more times and consumes exactly one value: `--login`/`-l`, `--repo`/`-r`, `--remote`/`-R`, and `--output`/`-o`.

Each long option accepts `--long VALUE` or `--long=VALUE`. Each short option accepts only `-x VALUE`. Root-level options before `whoami`, attached short values, short `=` forms, and short-option clusters are not accepted.

## Outcomes

Allow only the accepted grammar at EOF under the execution boundary. Defer a missing or different route token, an operand, an unknown or misplaced option, a missing option value, an unsupported option form, a direct Tea assignment or redirect, an inherited executable function, path-qualified Tea, a non-external-path target, or an execution-boundary mismatch. This policy has no deny outcome.

## Threat model and non-goals

The threat model is normal, non-adversarial use of Tea `bcd62a1`; it does not establish trust in other transports or an incompatible binary. The scope does not validate option values or returned identity data, inspect output, establish server-side authorization, or constrain the authenticated identity's remote permissions. It does not authorize other Tea routes or direct API calls.

Sources: [`cmd/whoami.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/whoami.go) and [`cmd/flags/generic.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/flags/generic.go).
