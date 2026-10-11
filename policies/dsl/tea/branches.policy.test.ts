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

policyTest.test("directly permits one branch detail with every inherited parent flag", ({ policy }) => {
  for (const argv of [
    ["branches"],
    ["branch", "topic"],
    ["b", "--comments", "topic"],
    ["branches", "--comments=false", "topic"],
    ["branch", "topic", "--fields", "name"],
    ["b", "--fields=name", "topic"],
    ["branches", "--page", "2", "topic"],
    ["branch", "topic", "--page=2"],
    ["b", "-p", "2", "topic"],
    ["b", "--limit", "5", "topic"],
    ["branches", "--limit=5", "topic"],
    ["branch", "--lm", "5", "topic"],
    ["branches", "--lm=5", "topic"],
    ["branch", "topic", "-lm", "5"],
    ["b", "--login", "work", "topic"],
    ["branches", "--login=work", "topic"],
    ["branches", "topic", "--repo=owner/repo"],
    ["branch", "--repo", "owner/repo", "topic"],
    ["b", "-r", "owner/repo", "topic"],
    ["branch", "-R", "origin", "topic"],
    ["b", "--remote=origin", "topic"],
    ["b", "topic", "-o", "json"],
    ["branches", "--output=json", "topic"],
    ["branches", "--comments", "--comments=true", "topic"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("allow");
});

policyTest.test("directly defers child routes, invalid forms, and surplus branch details", ({ policy }) => {
  for (const argv of [
    ["branches", "list"],
    ["branch", "ls"],
    ["b", "protect", "topic"],
    ["branches", "P", "topic"],
    ["branch", "unprotect", "topic"],
    ["b", "U", "topic"],
    ["branches", "rename", "topic", "renamed"],
    ["branch", "rn", "topic", "renamed"],
    ["branches", "topic", "other"],
    ["--repo", "owner/repo", "branches", "topic"],
    ["branches", "--fields"],
    ["branches", "topic", "--page"],
    ["branches", "--comments", "topic", "other"],
    ["branches", "-fname", "topic"],
    ["branches", "-f=name", "topic"],
    ["branches", "-fp", "topic"],
    ["branches", "topic", "-lm5"],
    ["branches", "topic", "-lm=5"],
    ["branches", "topic", "--unknown"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

policyTest.test(
  "aggregate profile rejects root flags while allowing parent flags around a detail",
  profile,
  ({ evaluate }) => {
    for (const command of ["tea branches --repo owner/repo topic --page=2", "tea b topic --comments --lm 5 -o json"])
      expect(evaluate(command).decision, command).toBe("allow");

    for (const command of ["tea --repo owner/repo branches topic", "tea --comments branches topic"])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.property(
  "branch parent aliases preserve repeated flag placement without admitting a second detail",
  { ...profile, cases: 96, seed: 161 },
  ({ evaluate, random }) => {
    const parent = random.pick(["branches", "branch", "b"]);
    const detail = random.pick(["topic", "feature/one", "release-1"]);
    const first = random.pick([
      "--comments",
      "--comments=true",
      "--fields name",
      "--fields=name",
      "--page 2",
      "-p 2",
      "--lm=5",
      "-lm 5",
      "--login work",
      "-r owner/repo",
    ]);
    const second = random.pick(["--comments", "--output=json", "--page=3", "-R origin", "--limit 10"]);
    const command = random.pick([
      `tea ${parent} ${first} ${detail} ${second}`,
      `tea ${parent} ${detail} ${first} ${second}`,
      `tea ${parent} ${first} ${second} ${detail}`,
    ]);
    expect(evaluate(command).decision, command).toBe("allow");
    expect(evaluate(`${command} extra`).decision, `${command} extra`).toBe("defer");
  },
);
