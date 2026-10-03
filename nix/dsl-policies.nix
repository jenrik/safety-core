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
    githubHttp = "${policySources}/github/github-http.policy.json";
    kubectl = "${policySources}/kubernetes/kubectl.policy.json";
    unsupportedShellSource = "${policySources}/unsupported-shell-source.policy.json";
    genericReadOnly = "${policySources}/generic-read-only.policy.json";
    ghReadOnly = "${policySources}/github/gh-read-only.policy.json";
    helmReadOnly = "${policySources}/kubernetes/helm-read-only.policy.json";
    ghApi = "${policySources}/github/gh-api.policy.json";
    strictReadOnly = [
      "${policySources}/kubernetes/strict-argocd.policy.json"
      "${policySources}/containers/strict-cosign.policy.json"
      "${policySources}/containers/strict-crane.policy.json"
      "${policySources}/containers/strict-docker.policy.json"
      "${policySources}/jfrog/strict-jf.policy.json"
      "${policySources}/jfrog/strict-jfrog.policy.json"
      "${policySources}/kubernetes/strict-kubectl.policy.json"
      "${policySources}/nix/strict-nix.policy.json"
      "${policySources}/nix/strict-nix-env.policy.json"
      "${policySources}/nix/strict-nix-store.policy.json"
      "${policySources}/nix/nix-prefetch-url.policy.json"
      "${policySources}/strict-npm.policy.json"
      "${policySources}/kubernetes/strict-oc.policy.json"
      "${policySources}/strict-pip.policy.json"
      "${policySources}/containers/strict-podman.policy.json"
      "${policySources}/containers/strict-podman-compose.policy.json"
      "${policySources}/containers/strict-skopeo.policy.json"
      "${policySources}/strict-tofu.policy.json"
      "${policySources}/strict-uv.policy.json"
      "${policySources}/strict-yarn.policy.json"
    ];
  };
}
