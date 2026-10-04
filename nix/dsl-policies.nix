{ lib, stdenv }:
let
  policySourceRoot = ../policies/dsl;

  policySources = stdenv.mkDerivation {
    pname = "safety-core-policy-sources";
    version = "0";
    src = policySourceRoot;
    dontUnpack = true;
    installPhase = ''
      mkdir -p $out
      cp -r $src/. $out/
    '';
  };

  isPolicyFile = path: lib.hasSuffix ".policy.json" (builtins.baseNameOf path);
  relativePath = path: lib.removePrefix (toString policySourceRoot + "/") (toString path);

  # Discover every packaged DSL policy source so that adding a policy file is
  # sufficient to register and enable it; there is no hand-maintained list to
  # drift out of sync with policies/dsl.
  allPolicyFiles = lib.sort (a: b: toString a < toString b) (
    builtins.filter isPolicyFile (lib.filesystem.listFilesRecursive policySourceRoot)
  );

  policyFileArtifacts = map (path: "${policySources}/${relativePath path}") allPolicyFiles;
in
{
  inherit policySources;

  dslPolicies = {
    # Complete, deterministically ordered set of packaged DSL policy sources.
    # This is the default-enabled set: every packaged policy is loaded unless
    # the consuming module opts out by not enabling completePolicySources.
    all = policyFileArtifacts;
  };
}
