import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test("allows each exact completion generator in the aggregate profile", profile, ({ evaluate }) => {
  for (const command of ["tea completion bash", "tea completion zsh", "tea completion fish", "tea completion pwsh"])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("allows only the bare completion parent and defers malformed child forms", profile, ({ evaluate }) => {
  expect(evaluate("tea completion").decision).toBe("allow");
  for (const command of ["tea completion bash extra", "tea completion --unknown bash", "tea completion sh"])
    expect(evaluate(command).decision, command).toBe("defer");
});
