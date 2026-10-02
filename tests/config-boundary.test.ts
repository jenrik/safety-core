import { expect, test } from "bun:test";

import * as config from "../src/config.ts";

test("the public config boundary is the strict authoritative global config", () => {
  expect(config.loadGlobalPolicyConfig).toBeFunction();
  expect("loadBashProfileSnapshot" in config).toBe(false);
  expect("createBashProfileSnapshotSource" in config).toBe(false);
});
