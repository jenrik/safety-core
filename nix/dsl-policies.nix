{ stdenv }:
let
  policySources = stdenv.mkDerivation {
    pname = "safety-core-policy-sources";
    version = "0";
    src = ../policies/dsl;
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src/. $out/
    '';
  };
in
{
  inherit policySources;
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
      "${policySources}/nix/nix-prefetch-url.policy.json"
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
}
