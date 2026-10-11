# `tea completion pwsh` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This permission policy permits PowerShell completion text generation while
protecting all unrelated Tea commands and output-producing variants.

## Accepted command forms

It accepts exactly `tea completion pwsh` with zero operands and no options;
`pwsh` is the only accepted generator spelling and has no aliases or value
forms.

## Exclusions and threat model

Other routes, dashed tokens, operands, assignments, redirects, and
inherited functions defer. The policy covers ordinary non-adversarial Tea use,
not intentional alternate-client/API bypass.

## Assumptions and non-goals

It trusts the Tea basename and documented completion grammar and does not prove
binary provenance/version or inspect generated PowerShell script content.

## Decision behavior

Only exact direct input at argv EOF allows. All other cases defer; none deny.

Source: Tea enables framework completion in [`cmd/cmd.go` at `bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/cmd.go); the `completion pwsh` route is recorded in the [Tea inventory](README.md).
