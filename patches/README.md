# Patched Bash grammar

`tree-sitter-bash-time-coproc.patch` applies to `tree-sitter-bash` v0.25.1
(commit `a06c2e4415e9bc0346c6b86d401879ffb44058f7`). It adds explicit
`time_statement` and `coproc_statement` nodes, including a contextual external
token for reserved-word `time -p`, so safety-core does not recover reserved-word
syntax by rewriting or reparsing source.

`@safety-core/core` generates and includes `tree-sitter-bash.wasm` during its
`prepack` lifecycle step. The generator uses the version-pinned
`tree-sitter-bash` v0.25.1 npm input and `tree-sitter-cli` v0.26.11 development
dependency, applies this patch strictly, and requires SHA-256
`e9d5f7c623675e6c02b35973350f7be8d87d74f6a6ca1a40701654623af31a06`.

After `npm install`, package the core without Nix:

```sh
npm pack ./packages/core
```

The first `tree-sitter build --wasm` invocation downloads the WASI SDK used by
the pinned CLI. The digest check makes a changed compiler or grammar input fail
closed instead of publishing a different parser. Nix independently regenerates
its grammar from the pinned `tree-sitter` 0.26.9 package, the Nix-native WASI
cross toolchain, and locked npm grammar input; neither path consumes a checked-
in WASM file. The cross toolchain is built for the active Nix build host, so the
same derivation supports both x86_64-linux and aarch64-linux.

In a source checkout, run `bun run build:native-packages` before invoking the
core CLI or source adapters. `initBundledBashParser` then resolves the generated
grammar from `packages/core/` and the runtime through the root npm dependency;
packed core and standalone adapter bundles resolve the same assets from their
installed package or bundle root.
