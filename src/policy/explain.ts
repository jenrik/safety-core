import type { BashInitialEnvironment } from "../authorization.js";
import { completePolicyInitialEnvironment } from "../bash/policy-environment.js";

/**
 * How `safety-core explain` treats names the caller did not provide.
 *
 * - `verified` mirrors the live harness adapters: every unspecified name is
 *   proven unset, so the evaluation is fully hermetic and deterministic.
 * - `filtered` models an incomplete or redacted snapshot: only supplied names
 *   are known and every other name is unknown. It is a robustness surface for
 *   policy authors, not a reproduction of the adapter path.
 */
export type ExplainEnvironmentMode = "verified" | "filtered";

/** A `NAME=VALUE` pair supplied with `--env-var`. */
export interface ExplainEnvironmentAssignment {
  readonly name: string;
  readonly value: string;
}

export interface ExplainEnvironmentInput {
  readonly assignments?: readonly ExplainEnvironmentAssignment[];
  readonly mode?: ExplainEnvironmentMode;
  /** Capture the ambient environment only when the caller explicitly opts in. */
  readonly inheritEnv?: boolean;
  readonly ambient?: Readonly<Record<string, string | undefined>>;
}

/**
 * Build the policy-evaluation environment for `explain`.
 *
 * The result is hermetic by default: with no `--inherit-env` and no `--env-var`
 * the environment is empty and every name is treated per {@link ExplainEnvironmentMode}.
 * Supplied values pass through the same complete-harness transformation the
 * adapters apply, so exported-function shadow facts remain visible to policies.
 */
export function buildExplainEnvironment(input: ExplainEnvironmentInput = {}): BashInitialEnvironment {
  const values: Record<string, string> = {};
  if (input.inheritEnv === true && input.ambient !== undefined) {
    for (const [name, value] of Object.entries(input.ambient)) if (value !== undefined) values[name] = value;
  }
  for (const assignment of input.assignments ?? []) values[assignment.name] = assignment.value;
  const complete = completePolicyInitialEnvironment(values);
  if (complete.kind !== "verified") return complete;
  if ((input.mode ?? "verified") === "verified") return complete;
  return Object.freeze({ kind: "filtered", values: complete.values, unset: Object.freeze([]) });
}
