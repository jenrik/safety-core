import { analyzeKubectlInvocation } from "../../src/bash/policies/kubectl.js";
import type { BashPolicyEvent, GuardPolicyDecision, LoadedBashPolicy } from "../../src/policy/types.js";

type CodeGuardDefinition = Omit<LoadedBashPolicy, "source" | "layer" | "evaluate"> & {
  readonly apiVersion: 1;
  readonly layer: "guard";
  evaluate(event: BashPolicyEvent): GuardPolicyDecision;
};

const policy: CodeGuardDefinition = Object.freeze({
  apiVersion: 1,
  layer: "guard",
  select: Object.freeze([{ kind: "executable-basename", value: "kubectl" }]),
  evaluate(event) {
    if (event.kind !== "invocation" || event.executable?.kind !== "known" || basename(event.executable.value) !== "kubectl") return ignore();
    const decision = analyzeKubectlInvocation(event);
    if (decision.kind === "deny") return deny(decision.reason, event);
    if (decision.kind === "defer") return defer(event);
    return ignore();
  },
});

export default policy;

function deny(reason: string, event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>): GuardPolicyDecision {
  return Object.freeze({
    kind: "deny",
    reason: Object.freeze([{ kind: "literal", value: reason }]),
    audit: Object.freeze({ invocation: event }),
  });
}

function defer(event: Extract<BashPolicyEvent, { readonly kind: "invocation" }>): GuardPolicyDecision {
  return Object.freeze({
    kind: "defer",
    audit: Object.freeze({ invocation: event }),
  });
}

function ignore(): GuardPolicyDecision {
  return Object.freeze({ kind: "ignore" });
}

function basename(path: string): string {
  return path.split("/").filter(Boolean).at(-1) ?? "";
}
