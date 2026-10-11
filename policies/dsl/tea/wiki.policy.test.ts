import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

function directDecision(policy: ValidatedBashPolicy, argv: readonly string[]): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "tea" },
    executionTarget: "external-path",
    executableIdentity: {
      qualification: "incomplete",
      spelling: "tea",
      basename: "tea",
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: argv.map((value) => ({ kind: "known" as const, value })),
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  }).kind;
}

policyTest.test("directly routes safe wiki children and defers mutations or unknown dashed tokens", ({ policy }) => {
  expect(directDecision(policy, ["wiki", "list"])).toBe("ignore");
  expect(directDecision(policy, ["wiki", "--repo", "owner/repo", "ls"])).toBe("ignore");
  expect(directDecision(policy, ["wiki", "create", "Home"])).toBe("defer");
  expect(directDecision(policy, ["wiki", "--unknown", "list"])).toBe("defer");
});

policyTest.test("routes generic option forms to every safe wiki child alias", profile, ({ evaluate }) => {
  for (const command of [
    "tea wiki --repo owner/repo list",
    "tea wiki --repo=owner/repo ls",
    "tea wiki -r owner/repo view Home",
    "tea wiki -r owner/repo history Home",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("allows inherited wiki read flags only at their supported route states", profile, ({ evaluate }) => {
  for (const command of [
    "tea wiki --fields title list",
    "tea wiki list --page=2",
    "tea wiki list --lm 5",
    "tea wiki list -lm 5",
    "tea wiki --fields title view Home",
    "tea wiki view --page 2 Home",
    "tea wiki view Home --lm=5",
    "tea wiki revisions --fields title Home",
    "tea wiki history Home --page=2",
    "tea wiki revisions Home -lm 5",
  ])
    expect(evaluate(command).decision, command).toBe("allow");

  for (const command of [
    "tea --fields title wiki list",
    "tea --lm 5 wiki view Home",
    "tea wiki list -lm5",
    "tea wiki view Home -lmp 5",
    "tea wiki revisions Home --lm",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.test(
  "defers wiki mutations, unknown flags, and invalid leaf arity in the aggregate profile",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea wiki --repo owner/repo create Home",
      "tea wiki -rowner/repo c Home",
      "tea wiki --repo=owner/repo edit Home",
      "tea wiki -rowner/repo rm Home",
      "tea wiki --unknown list",
      "tea wiki view",
      "tea wiki view Home Extra",
      "tea wiki revisions Home Extra",
      "tea wiki list Extra",
    ])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.property(
  "safe wiki aliases remain allowed across generic routing forms",
  { ...profile, cases: 64, seed: 41 },
  ({ evaluate, random }) => {
    const option = random.pick(["--repo owner/repo", "--repo=owner/repo", "-r owner/repo"]);
    const command = random.pick([
      `tea wiki ${option} list`,
      `tea wiki ${option} ls`,
      `tea wiki ${option} view Home`,
      `tea wiki ${option} revisions Home`,
      `tea wiki ${option} history Home`,
    ]);
    expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.property(
  "wiki inherited pagination accepts only named separate or long-equals forms",
  { ...profile, cases: 64, seed: 44 },
  ({ evaluate, random }) => {
    const route = random.pick(["wiki list", "wiki view Home", "wiki revisions Home"]);
    const value = String(random.integer(1, 50));
    const option = random.pick([`--limit ${value}`, `--lm ${value}`, `--lm=${value}`, `-lm ${value}`]);
    const command = `tea ${route} ${option}`;
    expect(evaluate(command).decision, command).toBe("allow");
    expect(evaluate(`tea ${route} -lm${value}`).decision, command).toBe("defer");
  },
);
