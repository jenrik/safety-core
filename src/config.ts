// Shared runtime config for permission profiles (readOnlyBash, ghApiReadOnly,
// ...). Written by the safety-core home-manager module as one harness-agnostic
// file; read by every adapter that needs to decide whether a dynamic profile
// is currently enabled, instead of plumbing the toggle through each harness's
// own (differently-shaped) settings format.

import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface SafetyCoreProfileConfig {
  readOnlyBash?: boolean;
  ghApiReadOnly?: boolean;
}

/** Default profile-config path under $XDG_CONFIG_HOME (falling back to ~/.config). */
export function defaultProfileConfigPath(): string {
  const base = process.env.XDG_CONFIG_HOME ?? join(process.env.HOME ?? "", ".config");
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

/** True iff the named profile is enabled in the profile config. */
export function isProfileEnabled(
  name: keyof SafetyCoreProfileConfig,
  path?: string,
): boolean {
  return loadProfileConfig(path)[name] === true;
}
