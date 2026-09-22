import { analyzeSecretReadInvocation, analyzeSecretRedirectInvocation } from "../../src/bash/policies/secrets.js";
import type { BashPolicyEvent, GuardPolicyDecision, LoadedBashPolicy } from "../../src/policy/types.js";

type CodeGuardDefinition = Omit<LoadedBashPolicy, "source" | "layer" | "evaluate"> & {
  readonly apiVersion: 1;
  readonly layer: "guard";
  evaluate(event: BashPolicyEvent): GuardPolicyDecision;
};

const readers = new Set([
  "cat", "head", "tail", "less", "bat", "more", "view", "xxd", "od", "hexdump", "strings", "source", ".",
]);

const policy: CodeGuardDefinition = Object.freeze({
  apiVersion: 1,
  layer: "guard",
  select: Object.freeze([{ kind: "invocation" }]),
  evaluate(event) {
    if (event.kind !== "invocation") return ignore();
    const redirect = analyzeSecretRedirectInvocation(event);
    if (redirect.kind === "deny") return deny(redirect.evidence.reason, event);
    if (event.executable.kind !== "known" || !readers.has(basename(event.executable.value))) return ignore();
    const decision = analyzeSecretReadInvocation(event);
    return decision.kind === "deny" ? deny(decision.evidence.reason, event) : ignore();
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

function ignore(): GuardPolicyDecision {
  return Object.freeze({ kind: "ignore" });
}

function basename(path: string): string {
  return path.split("/").filter(Boolean).at(-1) ?? "";
}
