import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const author = readFileSync(resolve(root, ".opencode/agents/bash-policy-author.md"), "utf8");
const reviewer = readFileSync(resolve(root, ".opencode/agents/bash-policy-adversarial-reviewer.md"), "utf8");

test("Bash policy author requires sanitized safety-core CLI evidence", () => {
  expect(author).toContain("safety-core validate");
  expect(author).toContain("safety-core explain --json -- '<bash-source>'");
  expect(author).toContain("env -i PATH=\"$PATH\" SAFETY_CORE_CONFIG_HOME=/absolute/config-home safety-core");
  expect(author).toContain("CLI evidence");
});

test("Bash policy reviewer requires independently verifiable CLI evidence", () => {
  expect(reviewer).toContain("safety-core validate");
  expect(reviewer).toContain("safety-core explain --json -- '<bash-source>'");
  expect(reviewer).toContain("report the review as inconclusive");
  expect(reviewer).toContain("env -i PATH=\"$PATH\" SAFETY_CORE_CONFIG_HOME=/absolute/config-home safety-core");
});

test("property: both prompts retain co-located scope requirements for 1,024 policy names", () => {
  for (let seed = 0; seed < 1024; seed++) {
    const policyName = `policy-${seed.toString(36)}`;
    for (const prompt of [author, reviewer]) {
      const rendered = prompt.replaceAll("<policy_name>", policyName);
      expect(rendered, `seed ${seed}`).toContain(`${policyName}.scope.md`);
    }
  }
});
