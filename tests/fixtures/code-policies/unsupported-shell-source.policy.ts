import type { BashPolicyEvent, GuardPolicyDecision, LoadedBashPolicy } from "../../../src/policy/types.js";

type CodeGuardDefinition = Omit<LoadedBashPolicy, "source" | "layer" | "evaluate"> & {
  readonly apiVersion: 1;
  readonly layer: "guard";
  evaluate(event: BashPolicyEvent): GuardPolicyDecision;
};

const policy: CodeGuardDefinition = Object.freeze({
  apiVersion: 1,
  layer: "guard",
  select: Object.freeze([{ kind: "execution-gap" }]),
  evaluate(event) {
    if (event.kind !== "execution-gap" || event.reason !== "unsupported-shell-source") return ignore();
    return Object.freeze({
      kind: "deny",
      reason: Object.freeze([{ kind: "literal", value: "fish command source is blocked until dedicated parser support is available" }]),
      audit: Object.freeze({ gap: event }),
    });
  },
});

export default policy;

function ignore(): GuardPolicyDecision {
  return Object.freeze({ kind: "ignore" });
}
