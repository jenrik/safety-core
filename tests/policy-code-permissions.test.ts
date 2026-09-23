import { expect, test } from "bun:test";

import fixture from "../policies/code/api-fixture.policy.ts";

test("trusted code-policy API fixture remains loadable without shipping permission policies", () => {
  expect(fixture).toMatchObject({ apiVersion: 1, layer: "permission", select: [{ kind: "invocation" }] });
  expect(fixture.evaluate()).toEqual({ kind: "ignore" });
});
