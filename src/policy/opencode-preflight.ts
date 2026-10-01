import type { BashPolicyEvaluation } from "../authorization.js";

export interface OpenCodeBashPreflight {
  readonly kind: "complete";
  readonly source: string;
  readonly cwd: string;
  /** Includes the command verdict and every stored file-permission verdict. */
  readonly evaluation: BashPolicyEvaluation;
}

export interface OpenCodeBashPreflightToken {
  readonly key: string;
  readonly sessionID: string;
}

export interface OpenCodeIndeterminatePreflight {
  readonly kind: "indeterminate";
  readonly decision: "deny" | "defer";
  readonly reason: "pending" | "overlapping-reuse" | "ambiguous-terminal" | "invalidated";
}

export type OpenCodeBashPreflightObservation = OpenCodeBashPreflight | OpenCodeIndeterminatePreflight;

type GenerationState =
  | { readonly kind: "active"; readonly token: OpenCodeBashPreflightToken; readonly source: string; readonly cwd: string;
    readonly result?: OpenCodeBashPreflight }
  | (OpenCodeIndeterminatePreflight & { readonly token: OpenCodeBashPreflightToken });

interface CallLedger {
  readonly sessionID: string;
  readonly generations: Map<OpenCodeBashPreflightToken, GenerationState>;
  /** Once requests overlap, call-ID-only permission callbacks remain ambiguous. */
  overlapping: boolean;
}

const AMBIGUOUS_EXECUTION = Symbol("ambiguous-opencode-execution");

/** Call identity locates a record; only an opaque execution identity can retire it. */
export function createOpenCodeBashPreflights() {
  const calls = new Map<string, CallLedger>();
  const executions = new WeakMap<object, Map<string, OpenCodeBashPreflightToken | typeof AMBIGUOUS_EXECUTION>>();
  return Object.freeze({
    begin(context: Readonly<Record<string, unknown>>, source: string, cwd: string, executionIdentity?: unknown): OpenCodeBashPreflightToken | undefined {
      const key = callKey(context);
      if (key === undefined) return undefined;
      const token = Object.freeze({ key, sessionID: context.sessionID as string });
      const identities = isObject(executionIdentity) ? executions.get(executionIdentity) : undefined;
      const reusedExecution = identities?.has(key) ?? false;
      const ledger = calls.get(key) ?? { sessionID: token.sessionID,
        generations: new Map<OpenCodeBashPreflightToken, GenerationState>(), overlapping: false };
      ledger.overlapping ||= ledger.generations.size > 0 || reusedExecution;
      if (isObject(executionIdentity)) {
        const bindings = identities ?? new Map();
        bindings.set(key, reusedExecution ? AMBIGUOUS_EXECUTION : token);
        executions.set(executionIdentity, bindings);
      }
      ledger.generations.set(token, Object.freeze({ kind: "active", token, source, cwd }));
      calls.set(key, ledger);
      return token;
    },
    complete(token: OpenCodeBashPreflightToken | undefined, evaluation: BashPolicyEvaluation): void {
      if (!token) return;
      const ledger = calls.get(token.key);
      const current = ledger?.generations.get(token);
      if (!ledger || !current) return;
      if (current.kind === "indeterminate") {
        // An uncorrelated terminal event must never be undone by a late allow.
        if (evaluation.decision === "deny") ledger.generations.set(token, Object.freeze({ ...current, decision: "deny" }));
        return;
      }
      ledger.generations.set(token, Object.freeze({ ...current, result: Object.freeze({ kind: "complete", source: current.source, cwd: current.cwd, evaluation }) }));
    },
    discard(token: OpenCodeBashPreflightToken | undefined): void {
      if (!token) return;
      const ledger = calls.get(token.key);
      const current = ledger?.generations.get(token);
      if (ledger && current) ledger.generations.set(token, indeterminate(current, "invalidated"));
    },
    get(context: Readonly<Record<string, unknown>>): OpenCodeBashPreflightObservation | undefined {
      const key = callKey(context);
      const ledger = key === undefined ? undefined : calls.get(key);
      if (!ledger) return undefined;
      const outstanding = [...ledger.generations.values()];
      if (ledger.overlapping) {
        const reason = outstanding.some((item) => item.kind === "indeterminate" && item.reason === "ambiguous-terminal") ? "ambiguous-terminal"
          : outstanding.every((item) => item.kind === "indeterminate" && item.reason === "invalidated") ? "invalidated" : "overlapping-reuse";
        return Object.freeze({ kind: "indeterminate", decision: outstanding.some(generationDenied) ? "deny" : "defer", reason });
      }
      const current = outstanding[0]!;
      if (current.kind === "indeterminate") return observation(current);
      return current.result ?? observation(indeterminate(current, "pending"));
    },
    finish(context: Readonly<Record<string, unknown>>, executionIdentity?: unknown): void {
      const key = callKey(context);
      if (key === undefined) return;
      const ledger = calls.get(key);
      if (!ledger) return;
      const execution = isObject(executionIdentity) ? executions.get(executionIdentity)?.get(key) : undefined;
      if (execution !== undefined && execution !== AMBIGUOUS_EXECUTION) {
        // Retirement removes exactly one generation. Newer and older pending
        // executions retain the call-level ambiguity until all are retired.
        ledger.generations.delete(execution);
        if (ledger.generations.size === 0) calls.delete(key);
        return;
      }
      // A session/call ID alone does not identify a retry generation. Drop
      // sensitive cached evidence, retain a restrictive lifecycle marker.
      for (const [token, current] of ledger.generations) ledger.generations.set(token, indeterminate(current, "ambiguous-terminal"));
    },
    clear(): void {
      for (const ledger of calls.values()) {
        for (const [token, current] of ledger.generations) ledger.generations.set(token, indeterminate(current, "invalidated"));
      }
    },
    clearSession(sessionID: string): void {
      for (const [key, ledger] of calls) if (ledger.sessionID === sessionID) calls.delete(key);
    },
  });
}

/** Final command/file defer maps to the existing whole-request Bash ask flow. */
export function openCodeBashPermissionStatus(
  preflight: OpenCodeBashPreflightObservation | undefined,
  nativeStatus: "allow" | "ask" | "deny",
): "allow" | "ask" | "deny" {
  if (nativeStatus === "deny" || preflight === undefined) return nativeStatus;
  if (preflight.kind === "indeterminate") return preflight.decision === "deny" ? "deny" : "ask";
  return preflight.evaluation.decision === "defer" ? "ask" : preflight.evaluation.decision;
}

function generationDenied(current: GenerationState): boolean {
  return current.kind === "indeterminate" ? current.decision === "deny" : current.result?.evaluation.decision === "deny";
}

function indeterminate(current: GenerationState, reason: OpenCodeIndeterminatePreflight["reason"]): OpenCodeIndeterminatePreflight & { readonly token: OpenCodeBashPreflightToken } {
  return Object.freeze({ kind: "indeterminate", token: current.token, decision: generationDenied(current) ? "deny" : "defer", reason });
}

function observation(current: OpenCodeIndeterminatePreflight): OpenCodeIndeterminatePreflight {
  return Object.freeze({ kind: current.kind, decision: current.decision, reason: current.reason });
}

function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null;
}

function callKey(context: Readonly<Record<string, unknown>>): string | undefined {
  return typeof context.sessionID === "string" && context.sessionID.length > 0 && typeof context.callID === "string" && context.callID.length > 0
    ? JSON.stringify([context.sessionID, context.callID]) : undefined;
}
