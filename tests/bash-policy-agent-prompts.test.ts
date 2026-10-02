import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const normalize = (text: string) => text.replace(/\s+/g, " ");
const author = normalize(readFileSync(resolve(root, ".opencode/agents/bash-policy-author.md"), "utf8"));
const reviewer = normalize(readFileSync(resolve(root, ".opencode/agents/bash-policy-adversarial-reviewer.md"), "utf8"));

test("Bash policy author requires sanitized safety-core CLI evidence", () => {
  expect(author).toContain("safety-core validate");
  expect(author).toContain("safety-core explain --json -- '<bash-source>'");
  expect(author).toContain("env -i PATH=\"$PATH\" safety-core --config /absolute/config.json");
  expect(author).not.toContain("SAFETY_CORE_CONFIG_HOME");
  expect(author).toContain("CLI evidence");
});

test("Bash policy reviewer requires independently verifiable CLI evidence", () => {
  expect(reviewer).toContain("bun src/cli.ts --config /absolute/config.json validate");
  expect(reviewer).toContain("bun src/cli.ts --config /absolute/config.json explain --json -- '<bash-source>'");
  expect(reviewer).toContain("report the review as inconclusive");
  expect(reviewer).toContain("env -i PATH=\"$PATH\" safety-core --config /absolute/config.json");
  expect(reviewer).not.toContain("SAFETY_CORE_CONFIG_HOME");
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
