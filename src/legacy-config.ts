import type { BashAnalysisLimits } from "./bash/runner.js";

export const STRICT_BASH_PROFILE_EXECUTABLES = Object.freeze([
  ["argocdReadOnly", "argocd"], ["cosignReadOnly", "cosign"], ["craneReadOnly", "crane"],
  ["dockerReadOnly", "docker"], ["jfrogReadOnly", "jf"], ["jfrogReadOnly", "jfrog"],
  ["kubectlReadOnly", "kubectl"], ["nixReadOnly", "nix"], ["nixEnvReadOnly", "nix-env"],
  ["nixStoreReadOnly", "nix-store"], ["ocReadOnly", "oc"], ["podmanReadOnly", "podman"],
  ["podmanComposeReadOnly", "podman-compose"], ["skopeoReadOnly", "skopeo"],
  ["tofuReadOnly", "tofu"], ["npmReadOnly", "npm"], ["pipReadOnly", "pip"],
  ["uvReadOnly", "uv"], ["yarnReadOnly", "yarn"],
] as const);

export type StrictBashProfile = (typeof STRICT_BASH_PROFILE_EXECUTABLES)[number][0];

export interface BashProfileSnapshot {
  readonly readOnlyBash: boolean;
  readonly ghApiReadOnly: boolean;
  readonly ghReadOnly: boolean;
  readonly helmReadOnly: boolean;
  readonly strictProfiles: Readonly<Record<StrictBashProfile, boolean>>;
  readonly ghPrCreate: {
    readonly enabled: boolean;
    readonly allowedRepositories: readonly string[];
    readonly allowedOrganizations: readonly string[];
  };
  readonly limits: BashAnalysisLimits;
}
