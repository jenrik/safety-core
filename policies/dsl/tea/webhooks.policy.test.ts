import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

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

policyTest.test("direct parent ignores list aliases so the aggregate evaluates the leaf", ({ policy }) => {
  for (const argv of [
    ["webhooks", "list"],
    ["webhook", "--repo", "owner/repo", "ls"],
    ["hooks", "--global", "list"],
    ["hook", "--org=team", "ls"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("ignore");
});

policyTest.test("allows the reviewed route with resolved and not-found PATH identities", ({ policy }) => {
  for (const identity of [resolvedTeaIdentity, incompleteTeaIdentity])
    expect(directDecision(policy, ["webhooks"], identity), identity.qualification).toBe("allow");
});

policyTest.test("aggregate profile still allows complete webhook list leaves", profile, ({ evaluate }) => {
  for (const command of [
    "tea webhooks list",
    "tea webhook --repo owner/repo ls",
    "tea hooks list --org=team",
    "tea hook ls --global",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("routes generic options before all webhook list aliases", profile, ({ evaluate }) => {
  for (const command of [
    "tea webhooks --repo owner/repo list",
    "tea webhook --repo=owner/repo ls",
    "tea hooks -r owner/repo list",
    "tea hook -r owner/repo ls",
    "tea webhooks list --org=team",
    "tea webhook ls --global",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("defers webhook mutations, unknown flags, and list operands", profile, ({ evaluate }) => {
  for (const command of [
    "tea webhooks --repo owner/repo create https://example.test/hook",
    "tea webhook --repo=owner/repo c https://example.test/hook",
    "tea hooks -rowner/repo delete 7",
    "tea hook -rowner/repo u 7",
    "tea webhooks --unknown list",
    "tea webhooks list unexpected",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.property(
  "webhook read aliases preserve inherited parent options before and after the list leaf",
  { ...profile, cases: 48, seed: 42 },
  ({ evaluate, random }) => {
    const parent = random.pick(["webhooks", "webhook", "hooks", "hook"]);
    const child = random.pick(["list", "ls"]);
    const option = random.pick([
      "--repo owner/repo",
      "--repo=owner/repo",
      "-r owner/repo",
      "--org team",
      "--org=team",
      "--global",
    ]);
    for (const command of [`tea ${parent} ${option} ${child}`, `tea ${parent} ${child} ${option}`])
      expect(evaluate(command).decision, command).toBe("allow");
  },
);
