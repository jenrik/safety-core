{
  lib,
  stdenv,
  buildNpmPackage,
  nodejs_22,
  esbuild,
  gnused,
}:
# Shared TypeScript core for the LLM safety hook, plus per-harness artifacts
# that wrap it for claude-code, pi, and opencode.
#
# Design notes
# ------------
# * The core lives under ./src. Each ./adapters/<harness>.ts (or subdirectory)
#   wires the core into a harness-specific API.
#
# * Pi and opencode load TypeScript at runtime. Their adapters import
#   `../src/index.js` relative to themselves — but when the adapter is loaded
#   through a symlink, jiti resolves relative imports from the symlink
#   location, not the realpath.  To avoid this we package each extension as a
#   *directory* with an index.ts at the root, rewriting adapter imports from
#   `../src/` to `./src/`.  The directory symlink means index.ts and src/ are
#   children of the symlink target, so relative resolution works regardless
#   of whether jiti resolves symlinks.
#
# * Claude Code invokes hooks as bare commands, so its adapters must be
#   self-contained node scripts. We esbuild-bundle each hook script into an
#   executable .mjs with a pinned node shebang; no runtime resolution needed.
#
# * Shell parsing is backed by tree-sitter-bash via web-tree-sitter (pure JS
#   WASM runtime — no native addons). We bundle the runtime and grammar WASM
#   files alongside the code. The web-tree-sitter JS module is placed in a
#   node_modules/ directory so Node's bare-specifier resolution finds it.
#   Both packages come from a dedicated dependency-only package manifest via
#   buildNpmPackage rather than hand-vendored fetchurl tarballs. Keeping this
#   lock separate prevents npm workspace entrypoints from becoming Nix runtime
#   dependencies.
let
  # ── npm dependencies ──────────────────────────────────────────────────
  nodeModules = buildNpmPackage {
    pname = "safety-core-deps";
    version = "0.0.0";
    src = ./nix/npm-deps;
    nodejs = nodejs_22;
    npmDepsHash = "sha256-vkdDnjq0AECm7lj/jsrGsaARqsw2PnuduJ7R88HmUc4=";
    dontNpmBuild = true;
    # tree-sitter-bash ships native-binding install scripts we don't need —
    # we only use its prebuilt tree-sitter-bash.wasm.
    npmFlags = [ "--ignore-scripts" ];
    installPhase = ''
      mkdir -p $out/node_modules
      cp -r node_modules/web-tree-sitter $out/node_modules/
      cp -r node_modules/tree-sitter-bash $out/node_modules/
    '';
  };

  # Lay out the files we need so that Node module resolution works
  # (`import "web-tree-sitter"` resolves to node_modules/web-tree-sitter/,
  # which carries its own package.json + exports map).
  wasmAssets = stdenv.mkDerivation {
    name = "safety-core-wasm";
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out/node_modules
      cp -r ${nodeModules}/node_modules/web-tree-sitter $out/node_modules/
      cp ${./tree-sitter-bash.wasm} $out/tree-sitter-bash.wasm
    '';
  };

  src = ./src;
  data = ./data;
  policySources = stdenv.mkDerivation {
    pname = "safety-core-policy-sources";
    version = "0";
    src = ./policies/dsl;
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src/. $out/
    '';
  };
  core = stdenv.mkDerivation {
    pname = "safety-core-core";
    version = "0";
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r ${src} $out/src
      cp -r ${data} $out/data
      cp -r ${wasmAssets}/node_modules $out/node_modules
      cp ${wasmAssets}/tree-sitter-bash.wasm $out/tree-sitter-bash.wasm
    '';
  };
  # A package-shaped view of the core lets native Pi and OpenCode artifacts
  # resolve parser assets from @safety-core/core, just like npm tarballs.
  coreNodePackage = stdenv.mkDerivation {
    name = "safety-core-core-node-package";
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r ${core}/src $out/
      cp -r ${core}/data $out/
      cp ${core}/tree-sitter-bash.wasm $out/
      cat > $out/package.json <<'EOF'
      {"name":"@safety-core/core","type":"module","exports":"./src/index.ts"}
      EOF
    '';
  };

  # Package a harness adapter as a directory extension (index.ts at root +
  # src/ + data/ + node_modules/ + WASM).  Rewrites `../src/` → `./src/` and
  # `../data/` → `./data/` in the adapter so it works when placed as
  # index.ts at the root of the output directory.
  mkExtensionDir = name: adapterFile: corePackage: stdenv.mkDerivation {
    name = "safety-core-${name}";
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out

      # Copy web-tree-sitter node_modules (for bare-specifier resolution).
      cp -r ${wasmAssets}/node_modules $out/

      # Copy WASM files to root (referenced by initBashParser).
      cp ${wasmAssets}/tree-sitter-bash.wasm $out/

       # Copy shared source and data.
       cp -r ${src} $out/src
       cp -r ${data} $out/data

       # Native package adapters resolve their shared implementation through
       # the same package boundary as the published npm artifact.
       if [ -n "${corePackage}" ]; then
         chmod u+w $out/node_modules
         mkdir -p $out/node_modules/@safety-core
         cp -r ${corePackage} $out/node_modules/@safety-core/core
       fi

       # Place the adapter as index.ts at the root, rewriting imports so they
       # resolve relative to the new location.
       ${gnused}/bin/sed 's|../src/|./src/|g; s|../data/|./data/|g' ${adapterFile} > $out/index.ts
     '';
  };

  piDir = mkExtensionDir "pi" ./adapters/pi.ts coreNodePackage;
  # OpenCode v1 and v2 receive independent extension directories. They share
  # behavior today but must remain separately packageable as their APIs evolve.
  opencodePlugin = mkExtensionDir "opencode" ./adapters/opencode.ts coreNodePackage;
  opencodeV2Plugin = mkExtensionDir "opencode-v2" ./adapters/opencode-v2.ts "";
  opencodeTuiPlugin = mkExtensionDir "opencode-tui" ./adapters/opencode-tui.ts coreNodePackage;

  # Trusted code policies are compiled independently. The loader rejects
  # relative imports, so every artifact must be self-contained at this boundary.
  mkCodePolicy = name: entry: stdenv.mkDerivation {
    pname = "safety-core-${name}-policy";
    version = "0";
    src = ./.;
    nativeBuildInputs = [ esbuild ];
    installPhase = ''
      mkdir -p $out
      esbuild \
        --bundle \
        --platform=node \
        --format=esm \
        --target=node20 \
        --outfile="$out/${name}.policy.mjs" \
        "$src/${entry}"
      if grep -Eq '^[[:space:]]*(import|export[[:space:]].*from)[[:space:]]' "$out/${name}.policy.mjs"; then
        echo "bundled policy retained a runtime import" >&2
        exit 1
      fi
    '';
  };
  mkGhPrCreateDslPolicy = { allowedRepositories, allowedOrganizations }: stdenv.mkDerivation {
    pname = "safety-core-gh-pr-create-dsl-policy";
    version = "0";
    src = ./.;
    nativeBuildInputs = [ nodejs_22 ];
    installPhase = ''
      mkdir -p $out
      ${nodejs_22}/bin/node ${./scripts/render-gh-pr-create-dsl.mjs} '${builtins.toJSON { inherit allowedRepositories allowedOrganizations; }}' > "$out/gh-pr-create.policy.json"
    '';
  };
in
{
  # Directory containing index.ts + src/ + WASM assets.  Home-manager
  # symlinks this as ~/.pi/agent/extensions/safety-hook/ so pi discovers
  # index.ts inside it.
  piExtensionDir = piDir;

  # Path to the OpenCode v1 adapter .ts file inside a store directory that also
  # contains ./src/, node_modules/, and WASM assets.
  opencodePluginFile = "${opencodePlugin}/index.ts";
  # Equivalent packaged artifact for the OpenCode v2 plugin API.
  opencodeV2PluginFile = "${opencodeV2Plugin}/index.ts";
  # Human-only TUI companion that emits the reload action to either server adapter.
  opencodeTuiPluginFile = "${opencodeTuiPlugin}/index.ts";
  inherit opencodePlugin opencodeV2Plugin opencodeTuiPlugin;

  # Not wired into harness configuration yet; Task 4 only produces trusted,
  # source-provenanced artifacts for loader and differential-policy testing.
  dslPolicies = {
    secretRead = "${policySources}/secret-read.policy.json";
    githubHttp = "${policySources}/github-http.policy.json";
    kubectl = "${policySources}/kubectl.policy.json";
    unsupportedShellSource = "${policySources}/unsupported-shell-source.policy.json";
    genericReadOnly = "${policySources}/generic-read-only.policy.json";
    ghReadOnly = "${policySources}/gh-read-only.policy.json";
    helmReadOnly = "${policySources}/helm-read-only.policy.json";
    ghApi = "${policySources}/gh-api.policy.json";
    strictReadOnly = [
      "${policySources}/strict-argocd.policy.json"
      "${policySources}/strict-cosign.policy.json"
      "${policySources}/strict-crane.policy.json"
      "${policySources}/strict-docker.policy.json"
      "${policySources}/strict-jf.policy.json"
      "${policySources}/strict-jfrog.policy.json"
      "${policySources}/strict-kubectl.policy.json"
      "${policySources}/strict-nix.policy.json"
      "${policySources}/strict-nix-env.policy.json"
      "${policySources}/strict-nix-store.policy.json"
      "${policySources}/strict-npm.policy.json"
      "${policySources}/strict-oc.policy.json"
      "${policySources}/strict-pip.policy.json"
      "${policySources}/strict-podman.policy.json"
      "${policySources}/strict-podman-compose.policy.json"
      "${policySources}/strict-skopeo.policy.json"
      "${policySources}/strict-tofu.policy.json"
      "${policySources}/strict-uv.policy.json"
      "${policySources}/strict-yarn.policy.json"
    ];
  };

  codePolicies = {
    apiFixture = mkCodePolicy "api-fixture" "policies/code/api-fixture.policy.ts";
  };

  inherit core policySources mkGhPrCreateDslPolicy;

  safetyCoreCli = stdenv.mkDerivation {
    pname = "safety-core";
    version = "0";
    src = ./.;
    nativeBuildInputs = [ esbuild ];
    installPhase = ''
      mkdir -p $out/bin $out/node_modules
      cp -r ${wasmAssets}/node_modules/web-tree-sitter $out/node_modules/
      cp ${wasmAssets}/tree-sitter-bash.wasm $out/tree-sitter-bash.wasm
      esbuild --bundle --platform=node --format=esm --target=node20 --external:web-tree-sitter --outfile="$out/bin/safety-core" --banner:js='#!${nodejs_22}/bin/node' "$src/src/cli.ts"
      chmod +x $out/bin/safety-core
    '';
  };

  # Standalone bundled hook scripts for claude-code. Produces a directory of
  # executable .mjs files matching the original .py names one-for-one.
  claudeCodeHooks = stdenv.mkDerivation {
    pname = "claude-code-safety-hooks";
    version = "0";
    src = ./.;
    nativeBuildInputs = [ esbuild ];
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
           --alias:@safety-core/core=./src/index.ts \
          --outfile="$out/$name.mjs" \
          --banner:js='#!${nodejs_22}/bin/node' \
          "$f"
        chmod +x "$out/$name.mjs"
      done
      runHook postBuild
    '';
    dontInstall = true;
  };
}
