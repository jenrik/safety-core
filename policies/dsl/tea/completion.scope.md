# `tea completion` policy scope

[Tea shared scope](scope.md) defines the common Tea assumptions and outcomes.

## Intent and protected asset

This permission policy permits only the completion parent help/default output
while protecting command execution from unreviewed completion subcommands.

## Accepted command forms

It accepts exactly `tea completion` with zero operands and no options. The
parent has no aliases, flags, value forms, or route-local operands.

## Exclusions and threat model

Every generator child, including `bash`, `zsh`, `fish`, and `pwsh`, defers to
its exact leaf. Unknown routes, dashed tokens, and operands defer.

## Assumptions and non-goals

The policy does not validate generated completion content.

## Decision behavior

Only exact direct parent input at argv EOF allows. Recognized generators are
ignored so their leaf policy can allow them; all other forms defer, and this
policy never denies.

Source: Tea enables the urfave CLI completion command in [`cmd/cmd.go` at `bcd62a1`](https://gitea.com/gitea/tea/src/commit/bcd62a1/cmd/cmd.go); the route inventory is [co-located](README.md).
