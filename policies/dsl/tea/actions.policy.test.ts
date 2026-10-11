import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

const inheritedOptions = [
  ["--repo", "owner/repo"],
  ["--repo=owner/repo"],
  ["--login", "work"],
  ["--login=work"],
  ["--output", "json"],
  ["--output=json"],
  ["-o", "json"],
] as const;

const rejectedInheritedOptions = [
  ["-r", "owner/repo"],
  ["--remote", "origin"],
  ["--remote=origin"],
  ["-R", "origin"],
  ["-l", "work"],
  ["-o=json"],
  ["-ojson"],
] as const;

const parentDefaults = [
  { parent: ["actions", "action"], namespace: [] },
  { parent: ["actions", "action"], namespace: ["secrets", "secret"] },
  { parent: ["actions", "action"], namespace: ["variables", "variable", "vars", "var"] },
  { parent: ["actions", "action"], namespace: ["runs", "run"] },
  { parent: ["actions", "action"], namespace: ["workflows", "workflow"] },
] as const;

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

policyTest.test("direct actions parent allows its pinned flags at EOF and defers every child route", ({ policy }) => {
  expect(directDecision(policy, ["actions"])).toBe("allow");
  expect(directDecision(policy, ["action"])).toBe("allow");

  for (const option of inheritedOptions) {
    const argv = ["actions", ...option];
    expect(directDecision(policy, argv), argv.join(" ")).toBe("allow");
  }

  for (const argv of [
    ["actions", "secrets"],
    ["actions", "variables"],
    ["actions", "runs"],
    ["actions", "workflows"],
    ["actions", "--unknown"],
    ...rejectedInheritedOptions.map((option) => ["actions", ...option]),
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

policyTest.test("all Actions parent/default routes accept only inherited flags at EOF", profile, ({ evaluate }) => {
  for (const route of parentDefaults) {
    for (const parent of route.parent) {
      for (const option of inheritedOptions) {
        const beforeNamespace =
          route.namespace.length === 0 ? [parent, ...option] : [parent, ...option, route.namespace[0]!];
        const afterNamespace =
          route.namespace.length === 0 ? beforeNamespace : [parent, route.namespace[0]!, ...option];
        for (const argv of [beforeNamespace, afterNamespace]) {
          const command = `tea ${argv.join(" ")}`;
          expect(evaluate(command).decision, command).toBe("allow");
        }
      }
      for (const option of rejectedInheritedOptions) {
        const beforeNamespace =
          route.namespace.length === 0 ? [parent, ...option] : [parent, ...option, route.namespace[0]!];
        const afterNamespace =
          route.namespace.length === 0 ? beforeNamespace : [parent, route.namespace[0]!, ...option];
        for (const argv of [beforeNamespace, afterNamespace]) {
          const command = `tea ${argv.join(" ")}`;
          expect(evaluate(command).decision, command).toBe("defer");
        }
      }
    }
  }
});

policyTest.property(
  "Actions parent/default inherited flags allow complete argv at EOF",
  { ...profile, cases: 192, seed: 219 },
  ({ evaluate, random }) => {
    const route = random.pick(parentDefaults);
    const parent = random.pick(route.parent);
    const options = Array.from({ length: random.integer(0, 5) }, () => random.pick(inheritedOptions));
    const split = random.integer(0, options.length);
    const before = options.slice(0, split).flat();
    const after = options.slice(split).flat();
    const argv =
      route.namespace.length === 0
        ? [parent, ...before, ...after]
        : [parent, ...before, random.pick(route.namespace), ...after];
    const command = `tea ${argv.join(" ")}`;
    expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.property(
  "Actions parent/default inherited flags reject excluded forms in either position",
  { ...profile, cases: 192, seed: 220 },
  ({ evaluate, random }) => {
    const route = random.pick(parentDefaults);
    const parent = random.pick(route.parent);
    const option = random.pick(rejectedInheritedOptions);
    const argv =
      route.namespace.length === 0 || random.boolean()
        ? [parent, ...option, ...(route.namespace.length === 0 ? [] : [random.pick(route.namespace)])]
        : [parent, random.pick(route.namespace), ...option];
    const command = `tea ${argv.join(" ")}`;
    expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.test(
  "aggregate profile allows action read aliases after every generic option form",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea actions --repo owner/repo secrets list",
      "tea action --repo=owner/repo variable ls",
      "tea actions runs --output json show 17",
      "tea action workflows --login=work get deploy",
      "tea actions secrets -o json list",
      "tea actions secrets list -l work",
      "tea action run show -r owner/repo 17",
      "tea actions workflow get --remote=origin deploy",
    ])
      expect(evaluate(command).decision, command).toBe("allow");
  },
);

const genericOptions = [
  { argv: ["--repo", "owner/repo"], inherited: true },
  { argv: ["--repo=owner/repo"], inherited: true },
  { argv: ["-r", "owner/repo"], inherited: false },
  { argv: ["--remote", "origin"], inherited: false },
  { argv: ["--remote=origin"], inherited: false },
  { argv: ["-R", "origin"], inherited: false },
  { argv: ["--login", "work"], inherited: true },
  { argv: ["--login=work"], inherited: true },
  { argv: ["-l", "work"], inherited: false },
  { argv: ["--output", "json"], inherited: true },
  { argv: ["--output=json"], inherited: true },
  { argv: ["-o", "json"], inherited: true },
] as const;

const inheritedRoutes = [
  { namespace: ["workflows", "workflow"], leaf: ["list", "ls"], argument: [] },
  { namespace: ["workflows", "workflow"], leaf: ["view", "show", "get"], argument: ["deploy"] },
  { namespace: ["runs", "run"], leaf: ["list", "ls"], argument: [] },
  { namespace: ["runs", "run"], leaf: ["view", "show", "get"], argument: ["17"] },
  { namespace: ["runs", "run"], leaf: ["logs", "log"], argument: ["17"] },
  { namespace: ["secrets", "secret"], leaf: ["list", "ls"], argument: [] },
  { namespace: ["variables", "variable", "vars", "var"], leaf: ["list", "ls"], argument: [] },
] as const;

policyTest.property(
  "Actions parent and leaf flags preserve parser-supported placement permutations",
  { ...profile, cases: 192, seed: 154 },
  ({ evaluate, random }) => {
    const parent = random.pick(["actions", "action"]);
    const route = random.pick(inheritedRoutes);
    const namespace = random.pick(route.namespace);
    const leaf = random.pick(route.leaf);
    const option = random.pick(genericOptions);
    const tail = route.argument;
    const commands = [
      { argv: [parent, ...option.argv, namespace, leaf, ...tail], decision: option.inherited ? "allow" : "defer" },
      { argv: [parent, namespace, ...option.argv, leaf, ...tail], decision: option.inherited ? "allow" : "defer" },
      { argv: [parent, namespace, leaf, ...option.argv, ...tail], decision: "allow" },
    ];
    for (const { argv, decision } of commands) {
      const command = `tea ${argv.join(" ")}`;
      expect(evaluate(command).decision, command).toBe(decision);
    }
  },
);

policyTest.test(
  "generic Actions inheritance does not admit root, child-only, attached, or clustered forms",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea -r owner/repo actions workflows list",
      "tea --remote=origin actions runs list",
      "tea actions -r owner/repo workflows list",
      "tea actions workflows -R origin list",
      "tea actions --page 2 runs list",
      "tea actions runs --page 2 list",
      "tea actions --name TOKEN variables list",
      "tea actions variables --name TOKEN list",
      "tea actions -rowner/repo workflows list",
      "tea actions workflows -Rorigin list",
      "tea actions -rR owner/repo workflows list",
      "tea actions workflows -rlo owner/repo list",
    ])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.test(
  "aggregate profile defers action mutations, unknown flags, and omitted leaf operands",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea actions --repo owner/repo secrets set TOKEN value",
      "tea action --repo=owner/repo variables update NAME value",
      "tea actions -rowner/repo runs cancel 17",
      "tea action -rlowner/repo workflows dispatch deploy",
      "tea actions --unknown secrets list",
      "tea actions runs --unknown view 17",
      "tea actions runs view",
      "tea actions runs logs",
      "tea actions workflows get",
    ])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.test("aggregate profile defers unsafe actions invocation forms", profile, ({ evaluate }) => {
  for (const command of [
    "FOO=bar tea actions secrets list",
    "tea actions secrets list > out",
    "/usr/bin/tea actions secrets list",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.property(
  "action read aliases retain aggregate coverage across routing forms",
  { ...profile, cases: 96, seed: 53 },
  ({ evaluate, random }) => {
    const route = random.pick([
      ["secrets", "secret"],
      ["variables", "variable", "vars", "var"],
      ["runs", "run"],
      ["workflows", "workflow"],
    ] as const);
    const parent = random.pick(["actions", "action"]);
    const child = random.pick(route);
    const option = random.pick(["--repo owner/repo", "--repo=owner/repo"]);
    const tail =
      child === "runs" || child === "run"
        ? random.pick(["list", "ls", "view 17", "show 17", "get 17", "logs 17", "log 17"])
        : child === "workflows" || child === "workflow"
          ? random.pick(["list", "ls", "view deploy", "show deploy", "get deploy"])
          : random.pick(["list", "ls"]);
    const command = `tea ${parent} ${option} ${child} ${tail}`;
    expect(evaluate(command).decision, command).toBe("allow");
  },
);
