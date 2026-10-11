# `tea completion bash` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This permission policy permits Bash completion text generation while protecting
all unrelated Tea commands and output-producing variants.

## Accepted command forms

It accepts exactly `tea completion bash` with zero operands and no options;
`bash` is the only accepted generator spelling and has no aliases or value
forms.

## Exclusions and threat model

Other routes, dashed tokens, operands, assignments, redirects, and
inherited functions defer. The policy models normal non-adversarial Tea use and
does not attempt to block intentional alternate-client execution.

## Assumptions and non-goals

Tea's basename and documented completion grammar are trusted. Binary
provenance/version and the safety or correctness of emitted script text are
outside scope.

## Decision behavior

Exact direct input at argv EOF allows; every other input defers. There is no
deny decision.

Source: Tea enables framework completion in [`cmd/cmd.go` at `bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/cmd.go); the `completion bash` route is recorded in the [Tea inventory](README.md).
