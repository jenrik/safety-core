import type { BashPolicyEvaluation } from "../authorization.js";
import type { LoadedPolicyRuntime } from "./runtime.js";

export interface ExplainTrace {
  readonly version: 1;
  readonly decision: BashPolicyEvaluation["decision"];
  readonly analysis: BashPolicyEvaluation["analysis"];
  readonly sources: readonly { readonly canonicalPath: string; readonly sha256: string }[];
  readonly events: BashPolicyEvaluation["events"];
  readonly decisions: BashPolicyEvaluation["traces"];
}

/** Preserve the complete modeled argv and environment for explicit local diagnostics. */
export function createExplainTrace(runtime: LoadedPolicyRuntime, evaluation: BashPolicyEvaluation): ExplainTrace {
  return Object.freeze({
    version: 1,
    decision: evaluation.decision,
    analysis: evaluation.analysis,
    sources: Object.freeze(runtime.policySet.sources.map((source) => Object.freeze({
      canonicalPath: source.canonicalPath,
      sha256: source.sha256,
    }))),
    events: evaluation.events,
    decisions: evaluation.traces,
  });
}

export function renderExplainTrace(trace: ExplainTrace, json: boolean): string {
  if (json) return `${JSON.stringify(trace, null, 2)}\n`;
  const lines = [
    `decision: ${trace.decision}`,
    `analysis: ${trace.analysis.complete ? "complete" : "incomplete"}`,
    "sources:",
    ...trace.sources.map((source) => `  ${source.sha256}  ${source.canonicalPath}`),
    "decisions:",
    ...trace.decisions.map((decision) => `  ${decision.layer} ${decision.decision.kind} ${decision.source.canonicalPath}`),
  ];
  return `${lines.join("\n")}\n`;
}
