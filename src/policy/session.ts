import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";

import {
  PolicyStartupError,
  type BashAnalysisConfig,
  type GlobalPolicyConfig,
  type PolicyConfigurationSource,
  type ResolvedPolicySource,
} from "./config.js";
import { loadPolicySources, type LoadedPolicySource } from "./load.js";
import type { LoadedPolicyRuntime } from "./runtime.js";

/** Serializable, immutable policy identity selected at session start. */
export interface PolicySessionManifest {
  readonly version: 1;
  readonly sessionID: string;
  readonly cwd: string;
  readonly projectRoot?: string;
  readonly configurations: readonly PolicyConfigurationSource[];
  readonly limits: BashAnalysisConfig;
  readonly sources: readonly LoadedPolicySource[];
}

/** Record the loaded policy set and selected project root for one harness session. */
export function createPolicySessionManifest(sessionID: string, runtime: LoadedPolicyRuntime, cwd: string): PolicySessionManifest {
  if (sessionID.length === 0) throw new PolicyStartupError("policy session manifest", "session ID must not be empty");
  return Object.freeze({
    version: 1,
    sessionID,
    cwd,
    ...(runtime.projectRoot === undefined ? {} : { projectRoot: runtime.projectRoot }),
    configurations: Object.freeze([...runtime.configurations]),
    limits: runtime.limits,
    sources: Object.freeze([...runtime.policySet.sources]),
  });
}

/** Parse untrusted persisted state into a checked, frozen session snapshot. */
export function parsePolicySessionManifest(value: unknown): PolicySessionManifest {
  if (!isRecord(value) || !Array.isArray(value.configurations) || !Array.isArray(value.sources)
    || !isRecord(value.limits)) {
    throw new PolicyStartupError("policy session manifest", "session snapshot is invalid");
  }
  const manifest = value as PolicySessionManifest;
  validatePolicySessionManifest(manifest);
  return Object.freeze({
    version: manifest.version,
    sessionID: manifest.sessionID,
    cwd: manifest.cwd,
    ...(manifest.projectRoot === undefined ? {} : { projectRoot: manifest.projectRoot }),
    configurations: Object.freeze(manifest.configurations.map((source) => Object.freeze({ ...source }))),
    limits: Object.freeze({ ...manifest.limits }),
    sources: Object.freeze(manifest.sources.map((source) => Object.freeze({ ...source }))),
  });
}

/**
 * Verify every byte referenced by an isolated-hook manifest before any policy
 * source is loaded. A changed, missing, or re-targeted path needs a new session.
 */
export function verifyPolicySessionSnapshot(manifest: PolicySessionManifest): void {
  validatePolicySessionManifest(manifest);
  for (const source of manifest.configurations) verifySourceBytes(source, "configuration");
  for (const source of manifest.sources) verifySourceBytes(source, "policy source");
}

/** Reload exactly an already-verified session snapshot without consulting live config. */
export async function loadPolicySessionRuntime(manifest: PolicySessionManifest): Promise<LoadedPolicyRuntime> {
  verifyPolicySessionSnapshot(manifest);
  const references: readonly ResolvedPolicySource[] = manifest.sources.map((source) => Object.freeze({ path: source.canonicalPath, scope: source.scope }));
  const policySet = await loadPolicySources(references);
  verifyLoadedSources(manifest.sources, policySet.sources);

  const globalConfiguration = manifest.configurations.find((source) => source.scope === "global");
  if (globalConfiguration === undefined) throw new PolicyStartupError("policy session manifest", "global configuration snapshot is missing");
  const config: GlobalPolicyConfig = Object.freeze({
    path: globalConfiguration.canonicalPath,
    configuration: globalConfiguration,
    version: 1,
    policies: Object.freeze(manifest.sources.filter((source) => source.scope === "global").map((source) => source.canonicalPath)),
    projectPolicies: Object.freeze({ mode: "disabled", allowedRoots: Object.freeze([]) }),
    bashAnalysis: manifest.limits,
  });
  return Object.freeze({
    config,
    policySet,
    limits: manifest.limits,
    ...(manifest.projectRoot === undefined ? {} : { projectRoot: manifest.projectRoot }),
    configurations: Object.freeze([...manifest.configurations]),
  });
}

export function validatePolicySessionManifest(manifest: PolicySessionManifest): void {
  if (manifest.version !== 1 || typeof manifest.sessionID !== "string" || manifest.sessionID.length === 0 || typeof manifest.cwd !== "string"
    || (manifest.projectRoot !== undefined && typeof manifest.projectRoot !== "string")
    || !Array.isArray(manifest.configurations) || !Array.isArray(manifest.sources) || !isValidLimits(manifest.limits)) {
    throw new PolicyStartupError("policy session manifest", "session snapshot is invalid");
  }
  const globalConfigurations = manifest.configurations.filter((source) => source.scope === "global");
  const projectConfigurations = manifest.configurations.filter((source) => source.scope === "project");
  if (globalConfigurations.length !== 1 || projectConfigurations.length > 1
    || (manifest.projectRoot === undefined) !== (projectConfigurations.length === 0)) {
    throw new PolicyStartupError("policy session manifest", "configuration snapshot is invalid");
  }
  validateSnapshotSources(manifest.configurations, "configuration");
  validateSnapshotSources(manifest.sources, "policy source");
  if (manifest.sources.some((source) => source.scope === "project" && !source.canonicalPath.endsWith(".policy.json"))) {
    throw new PolicyStartupError("policy session manifest", "policy source snapshot is invalid");
  }
}

function validateSnapshotSources(sources: readonly { readonly canonicalPath: string; readonly scope: string; readonly sha256: string }[], subject: string): void {
  const paths = new Set<string>();
  for (const source of sources) {
    if (!isSnapshotSource(source) || paths.has(source.canonicalPath)) {
      throw new PolicyStartupError("policy session manifest", `${subject} snapshot is invalid`);
    }
    paths.add(source.canonicalPath);
  }
}

function verifySourceBytes(source: { readonly canonicalPath: string; readonly sha256: string }, subject: string): void {
  let canonicalPath: string;
  let bytes: Buffer;
  try {
    canonicalPath = realpathSync(source.canonicalPath);
    bytes = readFileSync(canonicalPath);
  } catch (error) {
    throw new PolicyStartupError(source.canonicalPath, `cannot verify ${subject}`, error);
  }
  if (canonicalPath !== source.canonicalPath || digest(bytes) !== source.sha256) {
    throw new PolicyStartupError(source.canonicalPath, `${subject} digest changed since session startup`);
  }
}

function verifyLoadedSources(expected: readonly LoadedPolicySource[], actual: readonly LoadedPolicySource[]): void {
  if (actual.length === expected.length && actual.every((source, index) =>
    source.canonicalPath === expected[index]?.canonicalPath && source.sha256 === expected[index]?.sha256)) return;
  const path = actual.find((source, index) => source.sha256 !== expected[index]?.sha256)?.canonicalPath
    ?? expected[actual.length]?.canonicalPath
    ?? "policy session manifest";
  throw new PolicyStartupError(path, "policy source digest changed since session startup");
}

function isSnapshotSource(source: { readonly canonicalPath: string; readonly scope: string; readonly sha256: string }): boolean {
  return (source.scope === "global" || source.scope === "project")
    && (source.canonicalPath === "/" || (source.canonicalPath.startsWith("/") && source.canonicalPath.split("/").slice(1).every((part) => part !== "" && part !== "." && part !== "..")))
    && /^[a-f0-9]{64}$/.test(source.sha256);
}

function digest(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function isValidLimits(value: unknown): value is BashAnalysisConfig {
  if (!isRecord(value) || Object.keys(value).length !== 4) return false;
  return ["maxFunctionDepth", "maxNestedScriptDepth", "maxSteps", "maxWorkItems"].every((key) =>
    typeof value[key] === "number" && Number.isSafeInteger(value[key]) && value[key] > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
