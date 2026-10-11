# `tea completion fish` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This permission policy permits Fish completion text generation while protecting
all unrelated Tea commands and output-producing variants.

## Accepted command forms

It accepts exactly `tea completion fish` with zero operands and no options;
`fish` is the only accepted generator spelling and has no aliases or value
forms.

## Exclusions and threat model

Other routes, dashed tokens, operands, assignments, redirects, and
inherited functions defer. The model is normal non-adversarial Tea use, not a
deliberate attempt to execute another client or API.

## Assumptions and non-goals

The Tea basename and documented completion grammar are trusted. Binary
provenance/version and emitted completion script correctness are not verified.

## Decision behavior

Exact direct input at argv EOF allows. Every other form defers and none deny.

Source: Tea enables framework completion in [`cmd/cmd.go` at `bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/cmd.go); the `completion fish` route is recorded in the [Tea inventory](README.md).
