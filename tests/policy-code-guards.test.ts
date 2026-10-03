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

test("trusted code-policy fixture has no guard authority", () => {
  expect(fixture.layer).toBe("permission");
  expect(fixture.evaluate(event)).toEqual({ kind: "ignore" });
});
