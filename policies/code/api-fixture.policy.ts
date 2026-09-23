import type { BashPolicyEvent, PermissionBashPolicy, PolicyDecision } from "../../src/policy/types.js";

const policy: Omit<PermissionBashPolicy, "source" | "evaluate"> & { readonly apiVersion: 1; evaluate(event: BashPolicyEvent): PolicyDecision } = Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate: () => Object.freeze({ kind: "ignore" }),
});

export default policy;
