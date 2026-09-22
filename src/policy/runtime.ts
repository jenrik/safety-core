import type { BashInitialEnvironment, BashPolicyEvaluation } from "../authorization.js";
import { analyzeBashWithPolicies } from "../authorization.js";
import { loadGlobalPolicyConfig, resolveSessionPolicyConfig, type BashAnalysisConfig, type GlobalPolicyConfig } from "./config.js";
import { loadPolicySet, type LoadedPolicySet } from "./load.js";

export interface LoadedPolicyRuntime {
  readonly config: GlobalPolicyConfig;
  readonly policySet: LoadedPolicySet;
  readonly limits: BashAnalysisConfig;
}

/** Load the authoritative config and every policy source once for this runtime. */
export async function loadPolicyRuntime(cwd: string, env: Readonly<Record<string, string | undefined>> = process.env): Promise<LoadedPolicyRuntime> {
  const config = loadGlobalPolicyConfig(env);
  const resolved = resolveSessionPolicyConfig(config, cwd);
  const policySet = await loadPolicySet(resolved);
  return Object.freeze({ config, policySet, limits: config.bashAnalysis });
}

/** Evaluate a command against an already-loaded immutable policy set. */
export function evaluateLoadedPolicies(
  runtime: LoadedPolicyRuntime,
  source: string,
  initialEnvironment?: BashInitialEnvironment,
): BashPolicyEvaluation {
  return analyzeBashWithPolicies({
    source,
    limits: runtime.limits,
    initialEnvironment,
    policies: runtime.policySet.policies,
  });
}
