import type { NormalizedCommand } from "../bash/expand.js";
import { lookupBinding, modeledBindings, type Environment } from "../bash/environment.js";
import type { BashExecutionProvenance, ProcessEffect } from "../bash/walker.js";
import type { SourceSpan } from "../bash/cst.js";
import type { BashPolicyEvent, ExecutionGapView, InvocationView } from "./types.js";

export interface BashPolicyEventContext {
  readonly environment: Environment;
  readonly span: SourceSpan;
  readonly provenance: BashExecutionProvenance;
  readonly inPipeline: boolean;
  readonly processEffect: ProcessEffect;
}

/** Project the walker model into a complete, immutable policy-facing event. */
export function projectInvocationEvent(command: NormalizedCommand, context: BashPolicyEventContext): InvocationView {
  const environment = modeledBindings(command.environment);
  const assignments = immutableBindings(Object.fromEntries([...command.assignmentPatch.writes]
    .map((name) => [name, lookupBinding(command.assignmentPatch.environment, name).value])));
  return Object.freeze({
    kind: "invocation",
    executable: command.executable,
    argv: Object.freeze([...command.argv]),
    environment: immutableBindings(environment.values),
    exportedEnvironment: immutableExports(command.environment, environment.values),
    missingBindings: environment.missingBindings,
    redirects: Object.freeze([...command.redirects]),
    assignments: Object.freeze(assignments),
    span: copySpan(context.span),
    provenance: copyProvenance(context.provenance),
    inPipeline: context.inPipeline,
    processEffect: context.processEffect,
  });
}

/** Record a reachable child route which has no statically modeled invocation. */
export function projectExecutionGapEvent(reason: string, context: BashPolicyEventContext): ExecutionGapView {
  const environment = modeledBindings(context.environment);
  return Object.freeze({
    kind: "execution-gap",
    reason,
    environment: immutableBindings(environment.values),
    missingBindings: environment.missingBindings,
    span: copySpan(context.span),
    provenance: copyProvenance(context.provenance),
    inPipeline: context.inPipeline,
    processEffect: context.processEffect,
  });
}

export function appendPolicyEvent(events: BashPolicyEvent[], event: BashPolicyEvent): void {
  events.push(event);
}

function copySpan(span: SourceSpan): SourceSpan {
  return Object.freeze({ start: span.start, end: span.end });
}

function copyProvenance(provenance: BashExecutionProvenance): BashExecutionProvenance {
  return Object.freeze({ route: Object.freeze([...provenance.route]) });
}

function immutableBindings(bindings: Readonly<Record<string, import("../bash/environment.js").BindingValue>>): Readonly<Record<string, import("../bash/environment.js").BindingValue>> {
  return Object.freeze(Object.fromEntries(Object.entries(bindings).map(([name, value]) => [name, copyBindingValue(value)])));
}

function immutableExports(environment: Environment, bindings: Readonly<Record<string, import("../bash/environment.js").BindingValue>>): Readonly<Record<string, boolean>> {
  return Object.freeze(Object.fromEntries(Object.keys(bindings).map((name) => [name, lookupBinding(environment, name).exported])));
}

function copyBindingValue(value: import("../bash/environment.js").BindingValue): import("../bash/environment.js").BindingValue {
  if (value.kind === "known") return Object.freeze({ kind: "known", value: value.value });
  if (value.kind === "unset") return Object.freeze({ kind: "unset" });
  return Object.freeze({
    kind: "unknown",
    reason: Object.freeze({
      kind: value.reason.kind,
      ...(value.reason.span ? { span: Object.freeze({ start: value.reason.span.start, end: value.reason.span.end }) } : {}),
    }),
  });
}
