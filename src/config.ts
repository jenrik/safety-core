// Shared runtime config for permission profiles (readOnlyBash, ghApiReadOnly,
// ...). Written by the safety-core home-manager module as one harness-agnostic
// file; read by every adapter that needs to decide whether a dynamic profile
// is currently enabled, instead of plumbing the toggle through each harness's
// own (differently-shaped) settings format.

import { readFileSync } from "node:fs";
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
 * Load the profile config. Fails CLOSED: a missing, unreadable, or invalid
 * file returns `{}` (every profile reads as disabled), not an exception and
 * not a permissive default. This intentionally differs from this repo's
 * fail-open judge-provider convention -- there, failing open falls back to
 * asking a human; here, failing open would mean silently auto-allowing a
 * GitHub API write.
 */
export function loadProfileConfig(path: string = defaultProfileConfigPath()): SafetyCoreProfileConfig {
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * Load only validated structural analysis limits. Invalid or absent values use
 * the conservative, finite defaults rather than widening an analysis budget.
 */
export function loadBashAnalysisLimits(path?: string): BashAnalysisLimits {
  const configured = loadProfileConfig(path).bashAnalysis;
  return Object.freeze({
    maxFunctionDepth: positiveSafeInteger(configured?.maxFunctionDepth, DEFAULT_BASH_ANALYSIS_LIMITS.maxFunctionDepth),
    maxNestedScriptDepth: positiveSafeInteger(configured?.maxNestedScriptDepth, DEFAULT_BASH_ANALYSIS_LIMITS.maxNestedScriptDepth),
    maxSteps: positiveSafeInteger(configured?.maxSteps, DEFAULT_BASH_ANALYSIS_LIMITS.maxSteps),
    maxWorkItems: positiveSafeInteger(configured?.maxWorkItems, DEFAULT_BASH_ANALYSIS_LIMITS.maxWorkItems),
  });
}

/** True iff the named profile is enabled in the profile config. */
export function isProfileEnabled(
  name: keyof SafetyCoreProfileConfig,
  path?: string,
): boolean {
  return loadProfileConfig(path)[name] === true;
}

function positiveSafeInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : fallback;
}
