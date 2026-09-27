{ nodeModules, pkgs }:
let
  inherit (pkgs) lib stdenv nodejs_22 linkFarm tree-sitter writeShellScript;
  wasi32 = pkgs.pkgsCross.wasi32;

  # tree-sitter 0.26.9 passes the retired wasm32-unknown-wasi target. Nix's
  # portable cross toolchain targets its wasip1 successor by default.
  wasiClang = writeShellScript "safety-core-wasi-clang" ''
    args=()
    for arg in "$@"; do
      case "$arg" in
        --target=wasm32-unknown-wasi) ;;
        *) args+=("$arg") ;;
      esac
    done
    exec ${lib.getExe wasi32.stdenv.cc} "''${args[@]}"
  '';

  # tree-sitter only requires a WASI-compatible compiler at bin/clang. The
  # The Nix cross toolchain is native to each build host, unlike WASI SDK releases.
  wasiSdk = linkFarm "safety-core-wasi-sdk" {
    "bin/clang" = wasiClang;
  };
in
stdenv.mkDerivation {
  name = "safety-core-patched-tree-sitter-bash";
  dontUnpack = true;
  nativeBuildInputs = [ nodejs_22 wasi32.stdenv.cc.bintools tree-sitter ];
  TREE_SITTER_WASI_SDK_PATH = "${wasiSdk}";
  installPhase = ''
    test "$(tree-sitter --version)" = "tree-sitter 0.26.9"
    cp -r ${nodeModules}/node_modules/tree-sitter-bash grammar
    chmod -R u+w grammar
    patch --batch --directory=grammar -p1 < ${../patches/tree-sitter-bash-time-coproc.patch}
    mkdir -p $out
    (
      cd grammar
      tree-sitter generate
      tree-sitter build --wasm --output "$out/tree-sitter-bash.wasm"
    )
    echo '3cca2abc05942f0133e23b621d7aa9aa2f4cd367dd6e433947511da48a244bee  '$out'/tree-sitter-bash.wasm' | sha256sum --check
  '';
}
