{ pkgs }:
# Shared TypeScript core for the LLM safety hook, plus per-harness artifacts
# that wrap it for claude-code, pi, and opencode.
#
# Design notes
# ------------
# * The core lives under ./src. Each ./adapters/<harness>.ts (or subdirectory)
#   wires the core into a harness-specific API.
#
# * Pi and opencode load TypeScript at runtime. Their adapters import
#   `../src/index.js` — but Nix would import a bare `./adapters/foo.ts` file
#   as its own single-file store path with no surrounding directory, breaking
#   that relative import. We therefore package each adapter alongside its
#   src/ core files in a small runCommand-produced directory, and expose the
#   path to the adapter file *inside* that directory. Node's module resolver
#   follows the symlink back into the packaged directory where src/ lives.
#
# * Claude Code invokes hooks as bare commands, so its adapters must be
#   self-contained node scripts. We esbuild-bundle each hook script into an
#   executable .mjs with a pinned node shebang; no runtime resolution needed.
#
# * Shell parsing is backed by tree-sitter-bash via web-tree-sitter (pure JS
#   WASM runtime — no native addons). We bundle the runtime and grammar WASM
#   files alongside the code. The web-tree-sitter JS module is placed in a
#   node_modules/ directory so Node's bare-specifier resolution finds it.

let
  # ── WASM assets ───────────────────────────────────────────────────────
  # Fetch the web-tree-sitter npm package (pure JS + runtime WASM).
  webTreeSitter = pkgs.fetchurl {
    url = "https://registry.npmjs.org/web-tree-sitter/-/web-tree-sitter-0.26.11.tgz";
    hash = "sha256-GLYbTRpANvU1I+ktKUweB86lFQvjFrZU52pJbKUY8hE=";
  };

  # Fetch the tree-sitter-bash npm package (grammar WASM).
  treeSitterBash = pkgs.fetchurl {
    url = "https://registry.npmjs.org/tree-sitter-bash/-/tree-sitter-bash-0.25.1.tgz";
    hash = "sha256-1LKBlQjql8uJU//34wSmENRDAHvTlcjwOhXemorkpvk=";
  };

  # Extract the files we need from each tarball and lay them out so that
  # Node module resolution works (`import "web-tree-sitter"` resolves to
  # node_modules/web-tree-sitter/ which has a package.json and index.js).
  wasmAssets = pkgs.runCommand "safety-core-wasm" { } ''
    mkdir -p $out/node_modules/web-tree-sitter

    # web-tree-sitter.js → node_modules/web-tree-sitter/index.js
    ${pkgs.gnutar}/bin/tar -xzf ${webTreeSitter} -C $out/node_modules/web-tree-sitter \
      --strip-components=1 \
      package/web-tree-sitter.js \
      package/web-tree-sitter.d.ts \
      package/web-tree-sitter.wasm

    # Inject a minimal package.json for bare-specifier resolution.
    cat > $out/node_modules/web-tree-sitter/package.json << 'EOF'
    {
      "name": "web-tree-sitter",
      "version": "0.26.11",
      "main": "web-tree-sitter.js",
      "types": "web-tree-sitter.d.ts",
      "type": "module"
    }
    EOF

    # tree-sitter-bash WASM — placed at root alongside node_modules.
    ${pkgs.gnutar}/bin/tar -xzf ${treeSitterBash} -C $out \
      --strip-components=1 \
      package/tree-sitter-bash.wasm
  '';

  src = ./src;

  # Package an adapter .ts file next to a copy of the shared src/ core and
  # the WASM assets, so `../src/index.js` and `import "web-tree-sitter"`
  # resolve within the same store directory.
  mkAdapterDir = name: adapterFile: pkgs.runCommand "safety-core-${name}" { } ''
    mkdir -p $out/src $out/adapters

    # Copy web-tree-sitter node_modules (for bare-specifier resolution).
    cp -r ${wasmAssets}/node_modules $out/

    # Copy WASM files to root (referenced by initBashParser).
    cp ${wasmAssets}/tree-sitter-bash.wasm $out/

    # Copy source files.
    cp -r ${src}/. $out/src/
    cp ${adapterFile} $out/adapters/${builtins.baseNameOf adapterFile}
  '';

  piDir = mkAdapterDir "pi" ./adapters/pi.ts;
  opencodeDir = mkAdapterDir "opencode" ./adapters/opencode.ts;
in
{
  # Path to the pi adapter .ts file inside a store directory that also
  # contains ../src/, node_modules/, and WASM assets.
  piExtensionFile = "${piDir}/adapters/pi.ts";

  # Path to the opencode adapter .ts file inside a store directory that also
  # contains ../src/, node_modules/, and WASM assets.
  opencodePluginFile = "${opencodeDir}/adapters/opencode.ts";

  # Standalone bundled hook scripts for claude-code. Produces a directory of
  # executable .mjs files matching the original .py names one-for-one.
  claudeCodeHooks = pkgs.stdenv.mkDerivation {
    pname = "claude-code-safety-hooks";
    version = "0";
    src = ./.;
    nativeBuildInputs = [ pkgs.esbuild ];
    buildPhase = ''
      runHook preBuild
      mkdir -p $out

      # Copy WASM assets into the output directory so bundled adapters can
      # find them at runtime (relative to their own location).
      cp -r ${wasmAssets}/node_modules $out/
      cp ${wasmAssets}/tree-sitter-bash.wasm $out/

      for f in adapters/claude-code/*.ts; do
        name=$(basename "$f" .ts)
        # Underscore-prefixed files are shared internals, not hook entrypoints.
        case "$name" in _*) continue ;; esac
        esbuild \
          --bundle \
          --platform=node \
          --format=esm \
          --target=node20 \
          --external:web-tree-sitter \
          --outfile="$out/$name.mjs" \
          --banner:js='#!${pkgs.nodejs}/bin/node' \
          "$f"
        chmod +x "$out/$name.mjs"
      done
      runHook postBuild
    '';
    dontInstall = true;
  };
}
