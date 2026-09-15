import {
  createBashProfileSnapshotSource,
  evaluateConfiguredBash,
  type BashConfiguredEvaluation,
  type BashConfiguredOptions,
  type BashProfileSnapshotSource,
} from "../../src/index.js";
import type { HookEvent } from "./_shared.js";

export interface ClaudeBashPolicyDependencies {
  readonly evaluateConfiguredBash?: (options: BashConfiguredOptions) => BashConfiguredEvaluation;
  readonly profileSnapshotSource?: BashProfileSnapshotSource;
}

export type ClaudeBashPolicyDecision =
  | { readonly kind: "allow" | "deny"; readonly reason: string }
  | undefined;

const defaultDependencies: Required<ClaudeBashPolicyDependencies> = Object.freeze({
  evaluateConfiguredBash,
  profileSnapshotSource: createBashProfileSnapshotSource(),
});

/** A valid Bash PreToolUse event is the only input this adapter evaluates. */
export function isBashPreToolUse(event: HookEvent | null): boolean {
  return event?.hook_event_name === "PreToolUse"
    && event.tool_name === "Bash"
    && typeof event.tool_input?.command === "string";
}

/** Map one configured core evaluation to Claude's native permission override. */
export function evaluateClaudeBashPolicy(
  event: HookEvent,
  dependencies: ClaudeBashPolicyDependencies = defaultDependencies,
): ClaudeBashPolicyDecision {
  if (!isBashPreToolUse(event)) return undefined;
  const active = { ...defaultDependencies, ...dependencies };
  const command = event.tool_input!.command as string;
  const evaluation = active.evaluateConfiguredBash({
    source: command,
    initialEnvironment: { kind: "unavailable" },
    profileSnapshot: active.profileSnapshotSource.reloadIfChanged().snapshot,
  });
  if (evaluation.guards.kind === "block") return freeze({ kind: "deny", reason: evaluation.guards.reason });
  if (evaluation.permission.kind === "deny") return freeze({ kind: "deny", reason: evaluation.permission.reason });
  if (evaluation.permission.kind === "allow" && evaluation.analysis.status === "complete") {
    return freeze({ kind: "allow", reason: evaluation.permission.reason });
  }
  return undefined;
}

function freeze<T extends object>(value: T): T {
  return Object.freeze(value);
}
