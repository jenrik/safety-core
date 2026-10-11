import { expect } from "bun:test";
import { fileURLToPath } from "node:url";

import { createPolicyTestSuite } from "../../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../../src/policy/types.ts";

const testPath = fileURLToPath(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

function suiteFor(name: string) {
  return createPolicyTestSuite(fileURLToPath(new URL(`./${name}.policy.json`, import.meta.url)), testPath);
}

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

const grammars = [
  {
    name: "repos-list",
    allow: [
      ["repos", "list"],
      ["repo", "--owner", "tea", "ls"],
      ["repos", "ls", "--watched"],
      ["repos", "list", "-lm", "2"],
    ],
    defer: [
      ["repos", "list", "unexpected"],
      ["repos", "list", "--unknown"],
      ["repos", "list", "-fowner"],
    ],
  },
  {
    name: "organizations-list",
    allow: [
      ["organizations", "list"],
      ["org", "--page=2", "ls"],
      ["organization", "ls", "-r", "owner/repo"],
      ["organizations", "list", "-lm", "2"],
    ],
    defer: [
      ["organizations", "list", "unexpected"],
      ["organizations", "list", "--unknown"],
      ["organizations", "list", "-p2"],
    ],
  },
  {
    name: "actions-workflows-list",
    allow: [
      ["actions", "workflows", "list"],
      ["action", "--repo=owner/repo", "workflow", "ls"],
      ["actions", "workflows", "--login", "work", "list"],
      ["actions", "workflows", "ls", "-r", "owner/repo"],
    ],
    defer: [
      ["actions", "-r", "owner/repo", "workflows", "list"],
      ["actions", "workflows", "-R", "origin", "ls"],
      ["actions", "workflows", "list", "unexpected"],
      ["actions", "workflows", "list", "--unknown"],
    ],
  },
  {
    name: "actions-variables-list",
    allow: [
      ["actions", "variables", "list"],
      ["action", "--login", "work", "var", "ls", "--name=TOKEN"],
      ["actions", "variables", "ls", "-r", "owner/repo"],
    ],
    defer: [
      ["actions", "variables", "list", "TOKEN"],
      ["actions", "variables", "list", "--unknown"],
      ["actions", "variables", "list", "--name"],
    ],
  },
  {
    name: "actions-secrets-list",
    allow: [
      ["actions", "secrets", "list"],
      ["action", "--repo", "owner/repo", "secret", "ls"],
      ["actions", "secrets", "ls", "--page=2"],
    ],
    defer: [
      ["actions", "secrets", "list", "TOKEN"],
      ["actions", "secrets", "list", "--unknown"],
      ["actions", "secrets", "list", "--page"],
    ],
  },
  {
    name: "actions-runs-list",
    allow: [
      ["actions", "runs", "list"],
      ["action", "--output=json", "run", "ls", "--status", "success"],
      ["actions", "runs", "ls", "--since=24h"],
    ],
    defer: [
      ["actions", "runs", "list", "17"],
      ["actions", "runs", "list", "--unknown"],
      ["actions", "runs", "list", "--actor"],
    ],
  },
  {
    name: "branches-list",
    allow: [
      ["branches", "list"],
      ["branch", "--page", "2", "ls"],
      ["branch", "--comments", "ls"],
      ["branch", "ls", "--comments"],
      ["b", "list", "--fields=name"],
      ["branches", "list", "-lm", "2"],
    ],
    defer: [
      ["branches", "list", "main"],
      ["branches", "list", "--unknown"],
    ],
  },
  {
    name: "repos-search",
    allow: [
      ["repos", "search"],
      ["repo", "search", "safety", "core"],
      ["repos", "s", "--topic", "policy"],
      ["repos", "search", "--watched"],
      ["repos", "search", "safety", "--starred"],
    ],
    defer: [
      ["repos", "search", "--repo", "owner/repo"],
      ["repos", "search", "--topic=value"],
      ["repos", "search", "-tpolicy"],
      ["repos", "-ws", "search"],
      ["repos", "search", "--unknown"],
    ],
  },
  {
    name: "times-list",
    allow: [
      ["times", "list"],
      ["time", "ls", "#17", "--total"],
      ["t", "--mine", "list", "--from=2024-01-01"],
      ["times", "list", "-lm", "2"],
    ],
    defer: [
      ["times", "list", "alice", "bob"],
      ["times", "list", "--unknown"],
      ["times", "list", "--from"],
      ["times", "list", "-tm"],
    ],
  },
  {
    name: "logins-helper-store",
    allow: [
      ["logins", "helper", "store"],
      ["login", "git-credential", "erase"],
    ],
    defer: [
      ["logins", "helper", "store", "unexpected"],
      ["logins", "helper", "store", "--login", "work"],
      ["logins", "helper", "setup"],
    ],
  },
] as const;

const paginationGrammars = [
  { name: "actions-runs-list", route: ["actions", "runs", "list"] },
  { name: "actions-secrets-list", route: ["actions", "secrets", "list"] },
  { name: "admin-users", route: ["admin", "users"] },
  { name: "admin-users-list", route: ["admin", "users", "list"] },
  { name: "branches-list", route: ["branches", "list"] },
  { name: "comments-list", route: ["comments", "list", "42"] },
  { name: "issues-list", route: ["issues", "list"] },
  { name: "labels-list", route: ["labels", "list"] },
  { name: "milestones-list", route: ["milestones", "list"] },
  { name: "notifications", route: ["notifications"] },
  { name: "notifications-ls", route: ["notifications", "list"] },
  { name: "organizations-list", route: ["organizations", "list"] },
  { name: "pulls-list", route: ["pulls", "list"] },
  { name: "releases-assets-list", route: ["releases", "assets", "list", "v1"] },
  { name: "releases-list", route: ["releases", "list"] },
  { name: "repos-list", route: ["repos", "list"] },
  { name: "repos-search", route: ["repos", "search", "safety"] },
  { name: "ssh-keys", route: ["ssh-keys"] },
  { name: "ssh-keys-list", route: ["ssh-keys", "list"] },
  { name: "times-list", route: ["times", "list"] },
  { name: "webhooks", route: ["webhooks"] },
  { name: "webhooks-list", route: ["webhooks", "list"] },
  { name: "wiki", route: ["wiki"] },
  { name: "wiki-list", route: ["wiki", "list"] },
  { name: "wiki-view", route: ["wiki", "view", "Home"] },
  { name: "wiki-revisions", route: ["wiki", "revisions", "Home"] },
] as const;

for (const grammar of grammars) {
  const suite = suiteFor(grammar.name);
  suite.test(`${grammar.name} directly accepts only its reviewed grammar`, ({ policy }) => {
    for (const argv of grammar.allow) expect(directDecision(policy, argv), argv.join(" ")).toBe("allow");
    for (const argv of grammar.defer) expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
  });
  suite.property(`${grammar.name} direct unknown tails fall through`, { cases: 32, seed: 67 }, ({ policy, random }) => {
    const argv = [...random.pick(grammar.allow), random.pick(["--unknown", "-xvalue"])];
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
  });
}

for (const grammar of paginationGrammars) {
  const suite = suiteFor(grammar.name);
  suite.test(
    `${grammar.name} accepts both pagination aliases without admitting root, attached, or clustered forms`,
    ({ policy }) => {
      for (const option of [["--limit", "2"], ["--lm", "2"], ["--lm=2"], ["-lm", "2"]])
        expect(
          directDecision(policy, [...grammar.route, ...option]),
          `${grammar.route.join(" ")} ${option.join(" ")}`,
        ).toBe("allow");
      expect(directDecision(policy, ["--lm", "2", ...grammar.route]), `--lm 2 ${grammar.route.join(" ")}`).toBe(
        "defer",
      );
      expect(directDecision(policy, [...grammar.route, "-lm2"]), `${grammar.route.join(" ")} -lm2`).toBe("defer");
      expect(directDecision(policy, [...grammar.route, "-lmp", "2"]), `${grammar.route.join(" ")} -lmp 2`).toBe(
        "defer",
      );
      expect(directDecision(policy, [...grammar.route, "--lm"]), `${grammar.route.join(" ")} --lm`).toBe("defer");
    },
  );
}

const aggregate = suiteFor("repos-list");
aggregate.property(
  "aggregate Tea profile preserves every reviewed wildcard-tail route",
  { ...profile, cases: 80, seed: 71 },
  ({ evaluate, random }) => {
    const grammar = random.pick(grammars);
    const command = `tea ${grammar.allow[0].join(" ")}`;
    expect(evaluate(command).decision, command).toBe("allow");
  },
);

aggregate.property(
  "aggregate Tea profile preserves both named pagination aliases",
  { ...profile, cases: 80, seed: 75 },
  ({ evaluate, random }) => {
    const grammar = random.pick(paginationGrammars);
    const option = random.pick(["--limit 2", "--lm 2", "--lm=2", "-lm 2"]);
    const command = `tea ${grammar.route.join(" ")} ${option}`;
    expect(evaluate(command).decision, command).toBe("allow");
    expect(evaluate(`tea ${grammar.route.join(" ")} -lm2`).decision, command).toBe("defer");
  },
);
