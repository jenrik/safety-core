import {
  evaluateLoadedPolicies,
  policyInitialEnvironment,
  type BashPolicyEvaluation,
  type LoadedPolicyRuntime,
} from "../../src/index.js";
import type { HookEvent } from "./_shared.js";

export interface ClaudeBashPolicyDependencies {
  readonly runtime: LoadedPolicyRuntime;
  readonly evaluatePolicies?: (runtime: LoadedPolicyRuntime, source: string) => BashPolicyEvaluation;
}

export type ClaudeBashPolicyDecision =
  | { readonly kind: "allow" | "deny"; readonly reason: string }
  | undefined;

export function isBashPreToolUse(event: HookEvent | null): boolean {
  return event?.hook_event_name === "PreToolUse" && event.tool_name === "Bash" && typeof event.tool_input?.command === "string";
}

/** Claude's native permission response is a direct mapping of the generic algebra. */
export function evaluateClaudeBashPolicy(event: HookEvent, dependencies: ClaudeBashPolicyDependencies): ClaudeBashPolicyDecision {
  if (!isBashPreToolUse(event)) return undefined;
  const source = event.tool_input!.command as string;
  const evaluation = (dependencies.evaluatePolicies ?? ((runtime, command) =>
    evaluateLoadedPolicies(runtime, command, policyInitialEnvironment(process.env))))(dependencies.runtime, source);
  if (evaluation.decision === "defer") return undefined;
  const trace = evaluation.decision === "deny" ? evaluation.traces.find((value) => value.decision.kind === "deny") : undefined;
  const reason = trace?.decision.reason?.map((part) => part.kind === "literal" ? part.value : String(part.value)).join("")
    ?? (evaluation.decision === "allow" ? "Bash policy fully covers this command" : "Bash policy denied this command");
  return Object.freeze({ kind: evaluation.decision, reason });
}
