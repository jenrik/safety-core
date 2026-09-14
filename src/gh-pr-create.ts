// gh pull-request creation compatibility adapter backed by the stateful walker.

import { loadProfileConfig, type GhPrCreateProfileConfig } from "./config.js";
import { analyzeBashAuthorization, type BashAuthorizationAnalysis, type BashAuthorizationContext } from "./authorization.js";
import { ghPrCreateHandler } from "./bash/handlers/command-gh-pr-create.js";
import { ghPrCreateShellHandlers } from "./bash/handlers/command-gh-pr-shell.js";
import { isBashParserInitialized } from "./shell.js";

export interface GhPrCreatePolicy {
  enabled: boolean;
  allowedRepositories: readonly string[];
  allowedOrganizations: readonly string[];
}

export type GhPrCreateDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "ignore" };

export function loadGhPrCreatePolicy(path?: string): GhPrCreatePolicy {
  const profile = loadProfileConfig(path).ghPrCreate;
  return {
    enabled: isRecord(profile) && profile.enabled === true,
    allowedRepositories: stringArray(profile?.allowedRepositories),
    allowedOrganizations: stringArray(profile?.allowedOrganizations),
  };
}

/**
 * Preserve the ghPrCreate deployment fail-closed behavior while ordinary
 * parser/word uncertainty remains neutral in the generic authorization API.
 */
export function analyzeGhPrCreateCommand(
  command: string,
  policy: GhPrCreatePolicy = loadGhPrCreatePolicy(),
  context: BashAuthorizationContext = {},
): GhPrCreateDecision {
  if (!policy.enabled) return { kind: "ignore" };
  if (!isBashParserInitialized()) {
    return {
      kind: "deny",
      reason: "Bash blocked: the ghPrCreate safety parser is unavailable. This indicates a damaged safety-core hook deployment; fix and redeploy the packaged hook before retrying.",
    };
  }
  const analysis = analyzeGhPrCreateAuthorization(command, policy, context);
  const policyEvidence = analysis.policies.find((evidence) => evidence.name === "gh-pr-create");
  if (!policyEvidence || policyEvidence.name !== "gh-pr-create") return { kind: "ignore" };
  if (policyEvidence.decision === "deny") return { kind: "deny", reason: policyEvidence.reason ?? "Pull-request creation is blocked" };
  if (analysis.verdict.kind === "allow") return { kind: "allow", reason: policyEvidence.reason ?? "gh pr create auto-allowed for an allowlisted repository" };
  return { kind: "deny", reason: "Pull-request creation must be the only command in this Bash invocation; run native gh pr create separately" };
}

/** Raw walker result for adapters that must map only a proven verdict. */
export function analyzeGhPrCreateAuthorization(
  command: string,
  policy: GhPrCreatePolicy,
  context: BashAuthorizationContext = {},
): BashAuthorizationAnalysis {
  return analyzeBashAuthorization({
    source: command,
    handlers: [ghPrCreateHandler(policy), ...ghPrCreateShellHandlers],
    includeBaseHandlers: false,
    ...context,
  });
}

function isRecord(value: unknown): value is GhPrCreateProfileConfig {
  return typeof value === "object" && value !== null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
