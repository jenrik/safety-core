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
let
  src = ./src;

  # Package an adapter .ts file next to a copy of the shared src/ core, so
  # `../src/index.js` from inside the adapter resolves within the same store
  # directory.
  mkAdapterDir = name: adapterFile: pkgs.runCommand "safety-core-${name}" { } ''
    mkdir -p $out/src $out/adapters
    cp -r ${src}/. $out/src/
    cp ${adapterFile} $out/adapters/${builtins.baseNameOf adapterFile}
  '';

  piDir = mkAdapterDir "pi" ./adapters/pi.ts;
  opencodeDir = mkAdapterDir "opencode" ./adapters/opencode.ts;
in
{
  # Path to the pi adapter .ts file inside a store directory that also
  # contains ../src/.
  piExtensionFile = "${piDir}/adapters/pi.ts";

  # Path to the opencode adapter .ts file inside a store directory that also
  # contains ../src/.
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
      for f in adapters/claude-code/*.ts; do
        name=$(basename "$f" .ts)
        # Underscore-prefixed files are shared internals, not hook entrypoints.
        case "$name" in _*) continue ;; esac
        esbuild \
          --bundle \
          --platform=node \
          --format=esm \
          --target=node20 \
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
