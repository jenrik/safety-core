import { expect, test } from "bun:test";

import fixture from "../policies/code/api-fixture.policy.ts";
import type { BashPolicyEvent } from "../src/policy/types.ts";

const event: BashPolicyEvent = {
  kind: "execution-gap",
  reason: "test fixture",
  environment: {},
  missingBindings: "unset",
  span: { start: 0, end: 0 },
  provenance: { route: ["direct"] },
  inPipeline: false,
  processEffect: "none",
};

test("trusted code-policy API fixture remains loadable without shipping permission policies", () => {
  expect(fixture).toMatchObject({ apiVersion: 1, layer: "permission", select: [{ kind: "invocation" }] });
  expect(fixture.evaluate(event)).toEqual({ kind: "ignore" });
});
