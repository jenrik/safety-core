import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test("routes SSH-key list aliases through generic login forms", profile, ({ evaluate }) => {
  for (const command of [
    "tea ssh-keys --login account list",
    "tea ssh-key --login=account ls",
    "tea ssh-keys -l account list",
    "tea ssh-key -l account ls",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("defers SSH-key mutations, unknown flags, and list operands", profile, ({ evaluate }) => {
  for (const command of [
    "tea ssh-keys --login account add key.pub",
    "tea ssh-key --login=account delete 1",
    "tea ssh-keys -laccount rm 1",
    "tea ssh-keys --unknown list",
    "tea ssh-keys list unexpected",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});
