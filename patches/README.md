# Patched Bash grammar

`tree-sitter-bash-time-coproc.patch` applies to `tree-sitter-bash` v0.25.1
(commit `a06c2e4415e9bc0346c6b86d401879ffb44058f7`). It adds explicit
`time_statement` and `coproc_statement` nodes, including a contextual external
token for reserved-word `time -p`, so safety-core does not recover reserved-word
syntax by rewriting or reparsing source.

The checked-in `tree-sitter-bash.wasm` was generated with tree-sitter CLI
0.26.11 and has SHA-256
`e9d5f7c623675e6c02b35973350f7be8d87d74f6a6ca1a40701654623af31a06`.

To regenerate it in a clean checkout of that upstream commit:

```sh
git apply /path/to/safety-core/patches/tree-sitter-bash-time-coproc.patch
nix shell nixpkgs#tree-sitter -c tree-sitter generate
nix shell nixpkgs#tree-sitter -c tree-sitter build --wasm -o /path/to/safety-core/tree-sitter-bash.wasm
sha256sum /path/to/safety-core/tree-sitter-bash.wasm
```
