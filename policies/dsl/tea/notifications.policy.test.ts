import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test("routes generic options before every notifications read child alias", profile, ({ evaluate }) => {
  for (const command of [
    "tea notifications --repo owner/repo list",
    "tea notification --repo=owner/repo ls",
    "tea n -r owner/repo list",
    "tea notifications -r owner/repo ls",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("defers notification state changes, unknown flags, and list operands", profile, ({ evaluate }) => {
  for (const command of [
    "tea notifications --repo owner/repo read 1",
    "tea notification --repo=owner/repo r 1",
    "tea n -rowner/repo unread 1",
    "tea notifications -rowner/repo pin 1",
    "tea notifications unpin 1",
    "tea notifications --unknown list",
    "tea notifications list unexpected",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});
