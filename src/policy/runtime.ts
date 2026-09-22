import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";

import type { BashInitialEnvironment, BashPolicyEvaluation } from "../authorization.js";
import { analyzeBashWithPolicies } from "../authorization.js";
import {
  PolicyStartupError,
  loadGlobalPolicyConfig,
  resolveSessionPolicyConfig,
  type BashAnalysisConfig,
  type GlobalPolicyConfig,
  type PolicyConfigurationSource,
  type ResolvedPolicySource,
} from "./config.js";
import { loadPolicySet, loadPolicySources, type LoadedPolicySet, type LoadedPolicySource } from "./load.js";
import type { ExecutableFilesystem } from "./filesystem.js";

export interface LoadedPolicyRuntime {
  readonly config: GlobalPolicyConfig;
  readonly policySet: LoadedPolicySet;
  readonly limits: BashAnalysisConfig;
  readonly projectRoot?: string;
  readonly configurations: readonly PolicyConfigurationSource[];
}

export interface PolicyRuntimeManifest {
  readonly version: 2;
  readonly cwd: string;
  readonly projectRoot?: string;
  readonly configurations: readonly PolicyConfigurationSource[];
  readonly limits: BashAnalysisConfig;
  readonly sources: readonly LoadedPolicySource[];
}

/** Load the authoritative config and every policy source once for this runtime. */
export async function loadPolicyRuntime(cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const config = loadGlobalPolicyConfig(env);
  const resolved = resolveSessionPolicyConfig(config, cwd);
  const policySet = await loadPolicySet(resolved);
  return Object.freeze({
    config,
    policySet,
    limits: config.bashAnalysis,
    ...(resolved.projectRoot === undefined ? {} : { projectRoot: resolved.projectRoot }),
    configurations: resolved.configurations,
  });
}

/** Create a serializable identity snapshot for a session-spanning adapter. */
export function policyRuntimeManifest(runtime: LoadedPolicyRuntime, cwd: string): PolicyRuntimeManifest {
  return Object.freeze({
    version: 2,
    cwd,
    ...(runtime.projectRoot === undefined ? {} : { projectRoot: runtime.projectRoot }),
    configurations: runtime.configurations,
    limits: runtime.limits,
    sources: runtime.policySet.sources,
  });
}

/** Reload exactly the sources selected at session startup and reject drift. */
export async function loadPolicyRuntimeManifest(manifest: PolicyRuntimeManifest): Promise<LoadedPolicyRuntime> {
  validateManifest(manifest);
  verifyConfigurationSources(manifest.configurations);
  const references: readonly ResolvedPolicySource[] = manifest.sources.map((source) => Object.freeze({ path: source.canonicalPath, scope: source.scope }));
  const policySet = await loadPolicySources(references);
  if (policySet.sources.length !== manifest.sources.length || policySet.sources.some((source, index) =>
    source.canonicalPath !== manifest.sources[index]?.canonicalPath || source.sha256 !== manifest.sources[index]?.sha256)) {
    const path = policySet.sources.find((source, index) => source.sha256 !== manifest.sources[index]?.sha256)?.canonicalPath
      ?? manifest.sources[policySet.sources.length]?.canonicalPath
      ?? manifest.configurations[0]?.canonicalPath
      ?? "policy session manifest";
    throw new PolicyStartupError(path, "policy source digest changed since session startup");
  }
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

/** Evaluate a command against an already-loaded immutable policy set. */
export function evaluateLoadedPolicies(
  runtime: LoadedPolicyRuntime,
  source: string,
  initialEnvironment?: BashInitialEnvironment,
  context: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem } = {},
): BashPolicyEvaluation {
  return analyzeBashWithPolicies({
    source,
    limits: runtime.limits,
    initialEnvironment,
    cwd: context.cwd,
    executableFilesystem: context.executableFilesystem,
    policies: runtime.policySet.policies,
  });
}

function verifyConfigurationSources(sources: readonly PolicyConfigurationSource[]): void {
  for (const source of sources) {
    let canonicalPath: string;
    let bytes: Buffer;
    try {
      canonicalPath = realpathSync(source.canonicalPath);
      bytes = readFileSync(canonicalPath);
    } catch (error) {
      throw new PolicyStartupError(source.canonicalPath, "cannot verify configuration source", error);
    }
    if (canonicalPath !== source.canonicalPath || createHash("sha256").update(bytes).digest("hex") !== source.sha256) {
      throw new PolicyStartupError(source.canonicalPath, "configuration digest changed since session startup");
    }
  }
}

function validateManifest(manifest: PolicyRuntimeManifest): void {
  const globalConfigurations = manifest.configurations.filter((source) => source.scope === "global");
  const projectConfigurations = manifest.configurations.filter((source) => source.scope === "project");
  if (globalConfigurations.length !== 1 || projectConfigurations.length > 1
    || (manifest.projectRoot === undefined) !== (projectConfigurations.length === 0)) {
    throw new PolicyStartupError("policy session manifest", "configuration snapshot is invalid");
  }
  const configurationPaths = new Set<string>();
  for (const source of manifest.configurations) {
    if (!isSnapshotSource(source) || configurationPaths.has(source.canonicalPath)) {
      throw new PolicyStartupError("policy session manifest", "configuration snapshot is invalid");
    }
    configurationPaths.add(source.canonicalPath);
  }
  const sourcePaths = new Set<string>();
  for (const source of manifest.sources) {
    if (!isSnapshotSource(source) || sourcePaths.has(source.canonicalPath)
      || (source.scope === "project" && !source.canonicalPath.endsWith(".policy.json"))) {
      throw new PolicyStartupError("policy session manifest", "policy source snapshot is invalid");
    }
    sourcePaths.add(source.canonicalPath);
  }
}

function isSnapshotSource(source: { readonly canonicalPath: string; readonly scope: string; readonly sha256: string }): boolean {
  return (source.scope === "global" || source.scope === "project")
    && (source.canonicalPath === "/" || (source.canonicalPath.startsWith("/") && source.canonicalPath.split("/").slice(1).every((part) => part !== "" && part !== "." && part !== "..")))
    && /^[a-f0-9]{64}$/.test(source.sha256);
}
