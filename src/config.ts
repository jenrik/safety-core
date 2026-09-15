// Shared runtime config for permission profiles (readOnlyBash, ghApiReadOnly,
// ...). Written by the safety-core home-manager module as one harness-agnostic
// file; read by every adapter that needs to decide whether a dynamic profile
// is currently enabled, instead of plumbing the toggle through each harness's
// own (differently-shaped) settings format.
// The configured Bash evaluator loads one validated immutable snapshot per
// event. A process-lifetime snapshot remains a later lifecycle concern.

import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { DEFAULT_BASH_ANALYSIS_LIMITS, type BashAnalysisLimits } from "./bash/runner.js";

export interface SafetyCoreProfileConfig {
  readOnlyBash?: boolean;
  ghApiReadOnly?: boolean;
  ghReadOnly?: boolean;
  helmReadOnly?: boolean;
  argocdReadOnly?: boolean;
  cosignReadOnly?: boolean;
  craneReadOnly?: boolean;
  dockerReadOnly?: boolean;
  jfrogReadOnly?: boolean;
  kubectlReadOnly?: boolean;
  nixReadOnly?: boolean;
  nixEnvReadOnly?: boolean;
  nixStoreReadOnly?: boolean;
  ocReadOnly?: boolean;
  podmanReadOnly?: boolean;
  podmanComposeReadOnly?: boolean;
  skopeoReadOnly?: boolean;
  tofuReadOnly?: boolean;
  npmReadOnly?: boolean;
  pipReadOnly?: boolean;
  uvReadOnly?: boolean;
  yarnReadOnly?: boolean;
  ghPrCreate?: GhPrCreateProfileConfig;
  bashAnalysis?: BashAnalysisProfileConfig;
}

/** Runtime-configurable structural limits for the Bash authorization walker. */
export interface BashAnalysisProfileConfig {
  maxFunctionDepth?: number;
  maxNestedScriptDepth?: number;
  maxSteps?: number;
  maxWorkItems?: number;
}

/** Runtime representation of the `gh pr create` permission profile. */
export interface GhPrCreateProfileConfig {
  enabled?: boolean;
  allowedRepositories?: string[];
  allowedOrganizations?: string[];
}

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

export interface BashProfileSnapshotVersion {
  readonly generation: number;
  readonly snapshot: BashProfileSnapshot;
}

/** Adapter-owned lifecycle for a validated, atomically replaced profile snapshot. */
export interface BashProfileSnapshotSource {
  current(): BashProfileSnapshotVersion;
  reloadIfChanged(): BashProfileSnapshotVersion;
}

/**
 * Default profile-config path under $SAFETY_CORE_CONFIG_HOME, falling back
 * to $XDG_CONFIG_HOME, then ~/.config. SAFETY_CORE_CONFIG_HOME lets a
 * harness that overrides XDG_CONFIG_HOME for its own config isolation (e.g.
 * OpenCode2) still point safety-core at its real, shared profile config.
 */
export function defaultProfileConfigPath(): string {
  const base =
    process.env.SAFETY_CORE_CONFIG_HOME ??
    process.env.XDG_CONFIG_HOME ??
    join(process.env.HOME ?? "", ".config");
  return join(base, "safety-core", "profiles.json");
}

/**
 * Parse one immutable, event-local configuration snapshot for the configured
 * Bash evaluator. Invalid data can never enable an auto-allow profile.
 */
export function loadBashProfileSnapshot(path?: string): BashProfileSnapshot {
  try {
    return parseBashProfileSnapshot(JSON.parse(readFileSync(path ?? defaultProfileConfigPath(), "utf8"))) ?? disabledBashProfileSnapshot();
  } catch {
    return disabledBashProfileSnapshot();
  }
}

/**
 * Build a source that follows an atomically replaced Home Manager symlink
 * without resolving it once to the old Nix-store target.
 */
export function createBashProfileSnapshotSource(path: string = defaultProfileConfigPath()): BashProfileSnapshotSource {
  let version = freezeVersion(0, disabledBashProfileSnapshot());
  let fingerprint: string | null = null;

  function reloadIfChanged(): BashProfileSnapshotVersion {
    const stable = readStable(path);
    if (stable.fingerprint === fingerprint) return version;
    fingerprint = stable.fingerprint;
    version = freezeVersion(version.generation + 1, stable.source === null
      ? disabledBashProfileSnapshot()
      : parseBashProfileSnapshot(stable.source) ?? disabledBashProfileSnapshot());
    return version;
  }

  reloadIfChanged();
  return Object.freeze({ current: () => version, reloadIfChanged });
}

function parseBashProfileSnapshot(value: unknown): BashProfileSnapshot | null {
  if (!isRecord(value)) return null;
  const configured = value as SafetyCoreProfileConfig;
  if (!hasOnlyKeys(value, PROFILE_KEYS) || !optionalBoolean(configured.readOnlyBash) || !optionalBoolean(configured.ghApiReadOnly)
    || !optionalBoolean(configured.ghReadOnly) || !optionalBoolean(configured.helmReadOnly)
    || !validStrictProfiles(configured) || !validGhPrCreate(configured.ghPrCreate)
    || !validLimits(configured.bashAnalysis)) return null;
  const ghPrCreate = configured.ghPrCreate;
  const strictProfiles = Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, configured[profile] === true])) as Record<StrictBashProfile, boolean>;
  return Object.freeze({
    readOnlyBash: configured.readOnlyBash === true,
    ghApiReadOnly: configured.ghApiReadOnly === true,
    ghReadOnly: configured.ghReadOnly === true,
    helmReadOnly: configured.helmReadOnly === true,
    strictProfiles: Object.freeze(strictProfiles),
    ghPrCreate: Object.freeze({
      enabled: ghPrCreate?.enabled === true,
      allowedRepositories: Object.freeze(ghPrCreate?.allowedRepositories ?? []),
      allowedOrganizations: Object.freeze(ghPrCreate?.allowedOrganizations ?? []),
    }),
    limits: Object.freeze({
      maxFunctionDepth: configured.bashAnalysis?.maxFunctionDepth ?? DEFAULT_BASH_ANALYSIS_LIMITS.maxFunctionDepth,
      maxNestedScriptDepth: configured.bashAnalysis?.maxNestedScriptDepth ?? DEFAULT_BASH_ANALYSIS_LIMITS.maxNestedScriptDepth,
      maxSteps: configured.bashAnalysis?.maxSteps ?? DEFAULT_BASH_ANALYSIS_LIMITS.maxSteps,
      maxWorkItems: configured.bashAnalysis?.maxWorkItems ?? DEFAULT_BASH_ANALYSIS_LIMITS.maxWorkItems,
    }),
  });
}

function disabledBashProfileSnapshot(): BashProfileSnapshot {
  const strictProfiles = Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false])) as Record<StrictBashProfile, boolean>;
  return Object.freeze({
    readOnlyBash: false,
    ghApiReadOnly: false,
    ghReadOnly: false,
    helmReadOnly: false,
    strictProfiles: Object.freeze(strictProfiles),
    ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
    limits: Object.freeze({ ...DEFAULT_BASH_ANALYSIS_LIMITS }),
  });
}

function validStrictProfiles(configured: SafetyCoreProfileConfig): boolean {
  return STRICT_BASH_PROFILE_EXECUTABLES.every(([profile]) => optionalBoolean(configured[profile]));
}

function validGhPrCreate(value: unknown): value is GhPrCreateProfileConfig | undefined {
  return value === undefined || (isRecord(value) && hasOnlyKeys(value, GH_PR_CREATE_KEYS) && optionalBoolean(value.enabled)
    && optionalStringArray(value.allowedRepositories) && optionalStringArray(value.allowedOrganizations));
}

function validLimits(value: unknown): value is BashAnalysisProfileConfig | undefined {
  return value === undefined || (isRecord(value) && hasOnlyKeys(value, BASH_ANALYSIS_KEYS)
    && optionalPositiveSafeInteger(value.maxFunctionDepth)
    && optionalPositiveSafeInteger(value.maxNestedScriptDepth)
    && optionalPositiveSafeInteger(value.maxSteps)
    && optionalPositiveSafeInteger(value.maxWorkItems));
}

function optionalBoolean(value: unknown): boolean {
  return value === undefined || typeof value === "boolean";
}

function optionalStringArray(value: unknown): boolean {
  return value === undefined || (Array.isArray(value) && value.every((item) => typeof item === "string"));
}

function optionalPositiveSafeInteger(value: unknown): boolean {
  return value === undefined || (typeof value === "number" && Number.isSafeInteger(value) && value > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const PROFILE_KEYS = new Set<string>([
  "readOnlyBash", "ghApiReadOnly", "ghReadOnly", "helmReadOnly", "ghPrCreate", "bashAnalysis",
  ...STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => profile),
]);
const GH_PR_CREATE_KEYS = new Set(["enabled", "allowedRepositories", "allowedOrganizations"]);
const BASH_ANALYSIS_KEYS = new Set(["maxFunctionDepth", "maxNestedScriptDepth", "maxSteps", "maxWorkItems"]);

function hasOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function freezeVersion(generation: number, snapshot: BashProfileSnapshot): BashProfileSnapshotVersion {
  return Object.freeze({ generation, snapshot });
}

function readStable(path: string): { readonly fingerprint: string; readonly source: unknown | null } {
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = fingerprintFor(path);
    try {
      const source = JSON.parse(readFileSync(path, "utf8"));
      if (before === fingerprintFor(path)) return { fingerprint: before, source };
    } catch {
      if (before === fingerprintFor(path)) return { fingerprint: before, source: null };
    }
  }
  return { fingerprint: `${fingerprintFor(path)}:unstable`, source: null };
}

function fingerprintFor(path: string): string {
  try {
    const stat = statSync(path, { bigint: true });
    return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
  } catch {
    return "unavailable";
  }
}
