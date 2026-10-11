import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test(
  "routes generic options through both admin parents before safe list aliases",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea admin users --repo owner/repo list",
      "tea a u --repo=owner/repo ls",
      "tea admin users -r owner/repo list",
      "tea a u -r owner/repo ls",
    ])
      expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.test("defers admin-user mutations, unknown flags, and list operands", profile, ({ evaluate }) => {
  for (const command of [
    "tea admin users --repo owner/repo create alice",
    "tea a u --repo=owner/repo add alice",
    "tea admin users -rowner/repo update alice",
    "tea a u -rowner/repo rm alice",
    "tea admin --unknown users list",
    "tea admin users list unexpected",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.property(
  "admin aliases retain the aggregate allow for read leaves",
  { ...profile, cases: 48, seed: 43 },
  ({ evaluate, random }) => {
    const parent = random.pick(["admin", "a"]);
    const users = random.pick(["users", "u"]);
    const list = random.pick(["list", "ls"]);
    const option = random.pick(["--repo owner/repo", "--repo=owner/repo", "-r owner/repo"]);
    const command = `tea ${parent} ${users} ${option} ${list}`;
    expect(evaluate(command).decision, command).toBe("allow");
  },
);
