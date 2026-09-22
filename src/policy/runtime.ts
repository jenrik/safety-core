import type { BashInitialEnvironment, BashPolicyEvaluation } from "../authorization.js";
import { analyzeBashWithPolicies } from "../authorization.js";
import {
  PolicyStartupError,
  loadGlobalPolicyConfig,
  resolveSessionPolicyConfig,
  type BashAnalysisConfig,
  type GlobalPolicyConfig,
  type ResolvedPolicySource,
} from "./config.js";
import { loadPolicySet, loadPolicySources, type LoadedPolicySet, type LoadedPolicySource } from "./load.js";
import type { ExecutableFilesystem } from "./filesystem.js";

export interface LoadedPolicyRuntime {
  readonly config: GlobalPolicyConfig;
  readonly policySet: LoadedPolicySet;
  readonly limits: BashAnalysisConfig;
}

export interface PolicyRuntimeManifest {
  readonly version: 1;
  readonly cwd: string;
  readonly configPath: string;
  readonly limits: BashAnalysisConfig;
  readonly sources: readonly LoadedPolicySource[];
}

/** Load the authoritative config and every policy source once for this runtime. */
export async function loadPolicyRuntime(cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const config = loadGlobalPolicyConfig(env);
  const resolved = resolveSessionPolicyConfig(config, cwd);
  const policySet = await loadPolicySet(resolved);
  return Object.freeze({ config, policySet, limits: config.bashAnalysis });
}

/** Create a serializable identity snapshot for a session-spanning adapter. */
export function policyRuntimeManifest(runtime: LoadedPolicyRuntime, cwd: string): PolicyRuntimeManifest {
  return Object.freeze({
    version: 1,
    cwd,
    configPath: runtime.config.path,
    limits: runtime.limits,
    sources: runtime.policySet.sources,
  });
}

/** Reload exactly the sources selected at session startup and reject drift. */
export async function loadPolicyRuntimeManifest(manifest: PolicyRuntimeManifest): Promise<LoadedPolicyRuntime> {
  const references: readonly ResolvedPolicySource[] = manifest.sources.map((source) => Object.freeze({ path: source.canonicalPath, scope: "global" as const }));
  const policySet = await loadPolicySources(references);
  if (policySet.sources.length !== manifest.sources.length || policySet.sources.some((source, index) =>
    source.canonicalPath !== manifest.sources[index]?.canonicalPath || source.sha256 !== manifest.sources[index]?.sha256)) {
    const path = policySet.sources.find((source, index) => source.sha256 !== manifest.sources[index]?.sha256)?.canonicalPath
      ?? manifest.sources[policySet.sources.length]?.canonicalPath
      ?? manifest.configPath;
    throw new PolicyStartupError(path, "policy source digest changed since session startup");
  }
  const config: GlobalPolicyConfig = Object.freeze({
    path: manifest.configPath,
    version: 1,
    policies: Object.freeze(manifest.sources.map((source) => source.canonicalPath)),
    projectPolicies: Object.freeze({ mode: "disabled", allowedRoots: Object.freeze([]) }),
    bashAnalysis: manifest.limits,
  });
  return Object.freeze({ config, policySet, limits: manifest.limits });
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
