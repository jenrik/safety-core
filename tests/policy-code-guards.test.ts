import { expect, test } from "bun:test";

import fixture from "../policies/code/api-fixture.policy.ts";

test("trusted code-policy fixture has no guard authority", () => {
  expect(fixture.layer).toBe("permission");
  expect(fixture.evaluate()).toEqual({ kind: "ignore" });
});
