# `tea help` mandatory policy contract

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected assets

This permission policy permits rendering Tea help. It protects local Tea configuration and files, remote Gitea state, and every non-help Tea operation from being authorized by this route.


## Exact route and tail grammar

The route token is exactly `help` or its Tea alias `h`: `tea {help|h} TAIL...`. No root-level option may precede that token.

After the route token, `TAIL` is any sequence, including empty, of the following items in any order:

- A topic word that does not begin with `-`. Topic words may repeat; the policy does not validate their number or whether Tea recognizes them.
- `--login VALUE`, `--login=VALUE`, or `-l VALUE`.
- `--repo VALUE`, `--repo=VALUE`, or `-r VALUE`.
- `--remote VALUE`, `--remote=VALUE`, or `-R VALUE`.
- `--output VALUE`, `--output=VALUE`, or `-o VALUE`.

Each listed option requires exactly one value, may repeat, and may be interleaved with topic words. Separate option values are consumed as values even when they begin with `-`. Long options support only separate and `=` values; short options support only separate values. `-x=VALUE`, attached short values such as `-lVALUE`, and short clusters are not grammar forms.

Tea `bcd62a1` registers the help command and alias in [`cmd/cmd.go`](https://gitea.com/gitea/tea/src/commit/bcd62a1fb2ce6fdd51ebea91cc33ddbcae000b68/cmd/cmd.go). This contract describes the policy recognizer's accepted argv grammar; Tea remains responsible for interpreting recognized topic words and option values.

## Exclusions and threat model

The policy defers every non-help route, omitted route, root-level option, unknown option, dashed topic word, malformed option form, incomplete option value, and any surplus or otherwise unrecognized argument form.

The threat model is ordinary, non-adversarial use of the trusted Tea `bcd62a1` CLI. Deliberately selecting another executable, transport, or API client to evade this recognizer is outside scope.

## Assumptions and non-goals

This policy assumes the selected external Tea binary is compatible with the pinned commit. It does not attest binary provenance, validate topic words or option values, inspect help output, validate local configuration, establish remote authorization, or authorize any Tea mutation.

## Permit, defer, and deny behavior

- **Permit:** Only a complete argv matching the exact route and tail grammar at end of arguments, under the trusted execution assumption.
- **Defer:** Every argv or execution context outside that grammar or boundary, so another policy or the harness can decide it.
- **Deny:** Never. This permission policy has no deny outcome.
