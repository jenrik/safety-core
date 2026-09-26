# Native Node adapter package handoff

## Goal

Make harness integrations installable by non-Nix users through each harness's
native Node plugin mechanism. This is a distribution change: the shared policy
engine remains common, while harness entrypoints are published independently.

Nix remains the only policy distribution mechanism for now. No safety-core npm
package may ship policy files. A future native policy distributor should write
the existing safety-core configuration format and supply policy paths without
changing the adapter packages.

## Proposed package boundaries

- `@safety-core/core` owns the shared policy engine, configuration loader,
  parser initialization, `web-tree-sitter`, and `tree-sitter-bash.wasm`.
- `@safety-core/opencode-v1` provides the OpenCode v1 server and TUI plugin
  entrypoints.
- Reserve `@safety-core/opencode-v2` for the v2 adapter, but do not document a
  public native install flow until OpenCode publishes a stable external v2
  package-loader and TUI contract.

Shipping the WASM with `@safety-core/core` is preferred over a dedicated WASM
package. Parser initialization is a core responsibility, and one package avoids
an additional asset-version and resolution contract. The core package should
resolve the bundled asset from its installed package location rather than from
an adapter-relative copied directory.

## OpenCode v1

The current OpenCode integration has separate server and human-only TUI
entrypoints. They should be part of the same npm package, not independently
versioned safety-core packages:

```json
{
  "name": "@safety-core/opencode-v1",
  "type": "module",
  "exports": {
    "./server": "./dist/server.js",
    "./tui": "./dist/tui.js"
  }
}
```

The server entrypoint must default-export the OpenCode `{ id, server }` form;
the TUI entrypoint must default-export `{ id, tui }`. Both should use the same
stable plugin id. The TUI entrypoint registers the `/safety-reload` command and
publishes the existing reload event to the server plugin. It must remain
human-only and must not register an agent tool.

`@opencode-core/opencode-tui` is not a published package. The supported plugin
API package is `@opencode-ai/plugin`; its TUI type API is
`@opencode-ai/plugin/tui`. The current TUI adapter uses that API only for types,
so it does not need a bundled OpenCode/OpenTUI runtime. Keep the plugin API as a
development dependency for type-checking unless a future implementation needs a
runtime import. If that happens, use host-provided OpenTUI packages as peer
dependencies rather than bundling another renderer instance.

The expected v1 user installation flow is:

```sh
opencode plugin add @safety-core/opencode-v1
```

OpenCode's installer recognizes the `./server` and `./tui` exports and registers
them in the corresponding server and TUI configurations. Manual configuration
uses the package name in both plugin lists.

## OpenCode v2 constraint

OpenCode exposes experimental v2 authoring APIs, but its externally installable
plugin manifest and matching TUI contract are not yet sufficiently stable to
promise a public `@safety-core/opencode-v2` install flow. Keep the package name
reserved and its adapter code independent, but treat it as preview/internal
until upstream stabilizes this boundary.

## Pi

`@safety-core/pi` is a Pi package with one explicit native extension entrypoint:

```json
{
  "pi": {
    "extensions": ["./extensions/extension.js"]
  }
}
```

Install it with Pi's package manager:

```sh
pi install npm:@safety-core/pi
```

Pi provides `@earendil-works/pi-coding-agent`, `@earendil-works/pi-ai`,
`@earendil-works/pi-tui`, and `typebox` to extensions. They are development-only
dependencies for type checking and are deliberately neither bundled nor runtime
dependencies of this package. `@safety-core/core` remains its sole runtime
dependency. The extension keeps its existing `/safety-core` TUI-only settings
and session-local auto-approve/judge behavior.

## Claude Code

`@safety-core/claude-code` provides each existing hook as a Node executable and
as an export. Install it where the hook commands are on `PATH`:

```sh
npm install --global @safety-core/claude-code
```

For the immutable Bash policy hook, configure Claude Code with the same command
for both lifecycle events:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{ "type": "command", "command": "safety-core-claude-bash-policy" }]
    }],
    "SessionStart": [{
      "hooks": [{ "type": "command", "command": "safety-core-claude-bash-policy" }]
    }]
  }
}
```

The command receives Claude's hook-event JSON on stdin and preserves the native
stdout `hookSpecificOutput` and exit-code protocol. Other exported commands
retain the existing secrets, GitHub redirect, audit, and reminder behaviors.
The package has no Claude Code runtime dependency; it only requires Node and
`@safety-core/core`.

## Implementation work

1. Convert the repository's Node build layout into publishable package
   boundaries while retaining Nix as a consumer of the resulting artifacts.
2. Move parser asset discovery and packaging into `@safety-core/core` and test
   installation from a packed npm tarball, not only a workspace checkout.
3. Give the OpenCode v1 package `./server` and `./tui` exports, package-level
   integration tests, and a native install smoke test.
4. Keep policies absent from every npm tarball; add a test that fails if policy
   source files are included.
5. Defer the public v2 package contract pending upstream stabilization.
6. Publish Pi and Claude Code entrypoint packages without moving policy sources
   out of Nix distribution.

## Research references

- OpenCode plugin package: https://www.npmjs.com/package/@opencode-ai/plugin
- Upstream plugin manifest: https://github.com/anomalyco/opencode/blob/dev/packages/plugin/package.json
- Upstream TUI API: https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/tui.ts
- OpenCode v1 plugin documentation: https://opencode.ai/docs/plugins/
- Experimental v2 Promise API: https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/v2/promise/README.md
- Experimental v2 Effect API: https://github.com/anomalyco/opencode/blob/dev/packages/plugin/src/v2/effect/README.md
- Pi package documentation: https://pi.dev/docs/latest/packages
- Claude Code hooks reference: https://code.claude.com/docs/en/hooks
