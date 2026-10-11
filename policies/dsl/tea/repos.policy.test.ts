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

const flagForms = [
  ["--watched"],
  ["-w"],
  ["--starred"],
  ["-s"],
  ["--owner", "acme"],
  ["--owner=acme"],
  ["-O", "acme"],
  ["--fields", "owner,name"],
  ["--fields=owner,name"],
  ["-f", "owner,name"],
  ["--type", "fork"],
  ["--type=fork"],
  ["-T", "fork"],
  ["--page", "2"],
  ["--page=2"],
  ["-p", "2"],
  ["--limit", "25"],
  ["--limit=25"],
  ["--lm", "25"],
  ["--lm=25"],
  ["-lm", "25"],
  ["--login", "work"],
  ["--login=work"],
  ["-l", "work"],
  ["--output", "json"],
  ["--output=json"],
  ["-o", "json"],
] as const;

const childRoutes = [
  "list",
  "ls",
  "search",
  "s",
  "create",
  "c",
  "create-from-template",
  "ct",
  "fork",
  "f",
  "migrate",
  "m",
  "delete",
  "rm",
  "edit",
  "e",
] as const;

const mutatingChildRoutes = [
  "create",
  "c",
  "create-from-template",
  "ct",
  "fork",
  "f",
  "migrate",
  "m",
  "delete",
  "rm",
  "edit",
  "e",
] as const;

policyTest.test("directly allows the complete repos parent listing flags and one detail operand", ({ policy }) => {
  expect(directDecision(policy, ["repos"])).toBe("allow");
  expect(directDecision(policy, ["repo", "acme/project"])).toBe("allow");

  for (const flag of flagForms) {
    expect(directDecision(policy, ["repos", ...flag]), `repos ${flag.join(" ")}`).toBe("allow");
    expect(directDecision(policy, ["repo", "acme/project", ...flag]), `repo acme/project ${flag.join(" ")}`).toBe(
      "allow",
    );
  }
});

policyTest.test("directly defers unsupported repos flags, excessive operands, and child routes", ({ policy }) => {
  for (const argv of [
    ["repos", "--repo", "acme/project"],
    ["repos", "-r", "acme/project"],
    ["repos", "--remote=origin"],
    ["repos", "-R", "origin"],
    ["repos", "--watched=value"],
    ["repos", "--starred=value"],
    ["repos", "-wvalue"],
    ["repos", "--owner"],
    ["repos", "-Oacme"],
    ["repos", "acme/project", "extra"],
    ["repos", "acme/project", "--", "extra"],
    ...childRoutes.map((route) => ["repo", route]),
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

policyTest.property(
  "repos parent flags preserve aliases, supported forms, and placement around one detail operand",
  { cases: 128, seed: 208 },
  ({ policy, random }) => {
    const parent = random.pick(["repos", "repo"]);
    const flag = random.pick(flagForms);
    const detail = `acme/project-${random.integer(1, 999)}`;

    for (const argv of [
      [parent, ...flag, detail],
      [parent, detail, ...flag],
    ])
      expect(directDecision(policy, argv), argv.join(" ")).toBe("allow");
  },
);

policyTest.property(
  "repos parent preserves detail arity and defers every explicit child alias",
  { cases: 128, seed: 209 },
  ({ policy, random }) => {
    const parent = random.pick(["repos", "repo"]);
    const route = random.pick(childRoutes);
    const flag = random.pick(flagForms);
    const detail = `acme/project-${random.integer(1, 999)}`;

    for (const argv of [
      [parent, detail, "extra"],
      [parent, ...flag, route],
      [parent, route],
    ])
      expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
  },
);

policyTest.property(
  "aggregate profile still defers every mutating repos child alias",
  { ...profile, cases: 128, seed: 210 },
  ({ evaluate, random }) => {
    const parent = random.pick(["repos", "repo"]);
    const route = random.pick(mutatingChildRoutes);
    const flag = random.pick(flagForms);
    const command = `tea ${parent} ${flag.join(" ")} ${route}`;
    expect(evaluate(command).decision, command).toBe("defer");
  },
);
