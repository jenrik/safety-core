import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };

policyTest.test(
  "allows only one comments-list index across aliases and generic value forms",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea comments list --repo owner/repo 42",
      "tea comment ls --repo=owner/repo 42",
      "tea c list -r owner/repo 42",
      "tea comments ls -r owner/repo 42",
      "tea comments --repo owner/repo list 42",
      "tea comment -R origin ls 42",
      "tea c --login=work list 42",
      "tea comments -o json list 42",
      "tea comments list --page 2 42",
      "tea comments list --lm=5 42",
      "tea comments list -lm 5 42",
    ])
      expect(evaluate(command).decision, command).toBe("allow");
    for (const command of [
      "tea comments list",
      "tea comments list 42 extra",
      "tea comments --unknown list 42",
      "tea comments add 42",
      "tea --repo owner/repo comments list 42",
      "tea comments --lm 5 list 42",
      "tea comments -ro owner/repo list 42",
      "tea comments list -lm5 42",
      "tea comments list --lm 42",
    ])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.property(
  "comments parent flags precede list while pagination follows it",
  { ...profile, cases: 64, seed: 34 },
  ({ evaluate, random }) => {
    const index = String(random.integer(1, 500));
    const parentOption = random.pick(["--repo owner/repo", "--remote=origin", "--login work", "-o json"]);
    const pagination = random.pick([`--limit ${index}`, `--lm=${index}`, `-lm ${index}`]);
    const allowed = `tea comments ${parentOption} list ${pagination} ${index}`;
    expect(evaluate(allowed).decision, allowed).toBe("allow");
    const misplaced = `tea comments ${pagination} list ${index}`;
    expect(evaluate(misplaced).decision, misplaced).toBe("defer");
  },
);
