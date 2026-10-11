import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test("accepts only declared branch-list flags at the inherited parent and leaf", profile, ({ evaluate }) => {
  for (const command of [
    "tea branches --page 2 list",
    "tea branch --lm 5 ls",
    "tea b list --fields name",
    "tea branches list --repo owner/repo",
    "tea branches list --comments",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
  for (const command of [
    "tea --page 2 branches list",
    "tea branches list topic",
    "tea branches --state open list",
    "tea branches -p2 list",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.test("uses the pinned source grammar for corrected list routes", profile, ({ evaluate }) => {
  for (const command of [
    "tea notifications --lm 5 list",
    "tea webhooks --page 2 list",
    "tea ssh-keys --lm 5 list",
    "tea admin users --page 2 list",
    "tea wiki --page 2 list",
    "tea wiki revisions Home --page 2",
    "tea comments list 7 --page 2",
    "tea pulls --page 2 list",
    "tea labels --exclude-org list",
    "tea milestones --state open list",
    "tea releases list --page 2",
    "tea releases assets list v1 --page 2",
    "tea times --mine list",
    "tea organizations --page 2 list",
    "tea repos --type fork list",
    "tea repos search --watched",
    "tea repos search safety --starred",
    "tea webhooks list --org team",
    "tea webhooks ls --global",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
  for (const command of [
    "tea admin --page 2 users list",
    "tea comments --page 2 list 7",
    "tea releases --page 2 list",
    "tea labels --save list",
    "tea repos list operand",
    "tea times list alice extra",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.property(
  "valid parent pagination placements remain supported without root or attached-short forms",
  { ...profile, cases: 64, seed: 72 },
  ({ evaluate, random }) => {
    const [parent, child] = random.pick([
      ["branches", "list"],
      ["notifications", "list"],
      ["ssh-keys", "list"],
      ["organizations", "list"],
      ["repos", "list"],
    ] as const);
    const value = String(random.integer(1, 50));
    const command = `tea ${parent} ${random.pick(["--page", "-p"])} ${value} ${child}`;
    expect(evaluate(command).decision, command).toBe("allow");
    expect(evaluate(`tea --page ${value} ${parent} ${child}`).decision).toBe("defer");
    expect(evaluate(`tea ${parent} -p${value} ${child}`).decision).toBe("defer");
  },
);
