# `tea completion zsh` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This permission policy permits Zsh completion text generation while protecting
all unrelated Tea commands and output-producing variants.

## Accepted command forms

It accepts exactly `tea completion zsh` with zero operands and no options;
`zsh` is the only accepted generator spelling and has no aliases or value
forms.

## Exclusions and threat model

Other routes, dashed tokens, operands, assignments, redirects, and
inherited functions defer. It covers normal non-adversarial Tea usage, not
deliberate evasion through another executable or API.

## Assumptions and non-goals

The selected Tea basename and documented completion grammar are trusted. This
policy does not verify binary provenance/version or generated script content.

## Decision behavior

Only exact direct input at argv EOF allows. All other forms defer; none deny.

Source: Tea enables framework completion in [`cmd/cmd.go` at `bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/cmd.go); the `completion zsh` route is recorded in the [Tea inventory](README.md).
