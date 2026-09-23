# Task 12 Report: Complete Permission DSL Inventory

## Result

Production permission configuration now references only finite JSON DSL policy
sources. The legacy implementations were moved to `tests/fixtures/code-policies`
and are loaded only by differential tests. `policies/code` retains only
`api-fixture.policy.ts`, the minimal trusted-code loader fixture.

## DSL Sources

- Generated generic, Helm, and strict read-only policy sources cover every
  `STRICT_READ_ONLY_COMMANDS` family and its audited option grammar.
- The generated `gh-read-only.policy.json` is a 309-state finite trie generated
  from the pinned GitHub CLI command inventory, including native aliases and
  reserved `api` and `pr create` ownership routes.
- `gh-api.policy.json` covers method forms, GraphQL denial, malformed/unsafe
  parser forms, endpoint classification, pager proof, explicit execution paths,
  and environment routes.
- `renderGhPrCreateDslPolicy` produces canonical JSON from normalized and sorted
  repository and organization allowlists. It rejects malformed or duplicate
  identifiers and is covered by a source SHA-256 snapshot.

## Differential Coverage

`tests/policy-parity.test.ts` compares code-fixture and DSL decisions for:

- Generic and Helm commands, qualified paths, secret operands, and environment
  routes.
- Every strict command path with unknown flags and secret operands.
- Every pinned GH command path and native alias, plus extension, alias, unknown,
  qualified-path, and environment routes.
- GH API methods, endpoint forms, malformed fields, GraphQL endpoints, and
  pager/route behavior.
- PR creation allowlists, repository normalization, required noninteractive
  grammar, repeated non-repeatable flags, unsafe options, malformed arguments,
  and ownership of `gh api`.
- Deterministic option/alias/route permutations.

## DSL Runtime Changes

- Added `atEndOfArguments` so finite machines can allow only after consuming an
  accepted command grammar and defer unrecognized trailing options.
- Raised the fixed policy state ceiling from 128 to 512. The complete pinned GH
  command trie uses 309 states and remains below all fixed source, transition,
  and node limits.
- Corrected generic and strict generated machine terminal handling so unsafe
  Git options and unknown strict options cannot bypass audited tables.
- Corrected the policy-evaluation missing-binding fallback for hand-constructed
  events while preserving explicit environment-independent policy behavior.

## Verification

Passed:

```text
bun test
# 696 pass, 0 fail

bun test tests/policy-parity.test.ts tests/read-only-cli.test.ts \
  tests/git-read-only-policy.test.ts tests/gh-read-only-policy.test.ts \
  tests/gh-pr-create.test.ts tests/bash-gh-policies.test.ts \
  tests/bash-configured.test.ts tests/opencode-read-only-cli.test.ts
# 153 pass, 0 fail

nix flake check
# all checks passed
```

## Review Notes

- Production Nix sources remain DSL-only; test-only code fixtures are not
  exported through `package.nix`.
- The GH trie intentionally defers all non-owned GH routes because the pinned
  startup-side-effect model does not auto-authorize them. Its explicit inventory
  still preserves native-command and alias ownership rather than relying on a
  catch-all fallback.
- The source state-limit increase is bounded and documented; no dynamic
  execution, callbacks, filesystem access, or unbounded collections were added
  to the DSL runtime.
