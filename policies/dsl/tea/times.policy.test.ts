import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

function directDecision(
  policy: ValidatedBashPolicy,
  argv: readonly string[],
  executableIdentity: InvocationView["executableIdentity"] = incompleteTeaIdentity,
): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "tea" },
    executionTarget: "external-path",
    executableIdentity,
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

const incompleteTeaIdentity: InvocationView["executableIdentity"] = {
  qualification: "incomplete",
  spelling: "tea",
  basename: "tea",
  chain: [],
  failure: { kind: "not-found" },
};

const resolvedTeaIdentity: InvocationView["executableIdentity"] = {
  qualification: "known",
  spelling: "tea",
  basename: "tea",
  selectedPath: "/nix/store/tea/bin/tea",
  canonicalTarget: "/nix/store/tea/bin/tea",
  chain: [],
};

const optionForms = [
  ["--login", "work"],
  ["--login=work"],
  ["-l", "work"],
  ["--repo", "owner/repo"],
  ["--repo=owner/repo"],
  ["-r", "owner/repo"],
  ["--remote", "origin"],
  ["--remote=origin"],
  ["-R", "origin"],
  ["--output", "json"],
  ["--output=json"],
  ["-o", "json"],
] as const;

policyTest.test("directly allows bare times aliases and their inherited option forms", ({ policy }) => {
  for (const parent of ["times", "time", "t"]) {
    expect(directDecision(policy, [parent]), parent).toBe("allow");
    for (const option of optionForms)
      expect(directDecision(policy, [parent, ...option]), `${parent} ${option.join(" ")}`).toBe("allow");
  }
});

policyTest.test("allows the reviewed route with resolved and not-found PATH identities", ({ policy }) => {
  for (const identity of [resolvedTeaIdentity, incompleteTeaIdentity])
    expect(directDecision(policy, ["times"], identity), identity.qualification).toBe("allow");
});

policyTest.test("directly defers root, incomplete, attached, clustered, and child forms", ({ policy }) => {
  for (const argv of [
    ["--login", "work", "times"],
    ["times", "--login"],
    ["times", "-lwork"],
    ["times", "-l=work"],
    ["times", "-lR", "work"],
    ["times", "list"],
    ["time", "add"],
    ["t", "unexpected"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

policyTest.property(
  "times accepts repeated option forms after every parent alias",
  { cases: 96, seed: 313 },
  ({ policy, random }) => {
    const parent = random.pick(["times", "time", "t"]);
    const first = random.pick(optionForms);
    const second = random.pick(optionForms);
    const argv = [parent, ...first, ...second];
    expect(directDecision(policy, argv), argv.join(" ")).toBe("allow");
  },
);

policyTest.property(
  "times invalid option forms defer after every parent alias",
  { cases: 96, seed: 314 },
  ({ policy, random }) => {
    const parent = random.pick(["times", "time", "t"]);
    const suffix = random.pick([
      ["--repo"],
      ["-rowner/repo"],
      ["-r=owner/repo"],
      ["-rR", "owner/repo"],
      ["--output"],
      ["-ojson"],
      ["-o=json"],
      ["-ol", "json"],
    ] as const);
    const argv = [parent, ...suffix];
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
  },
);
