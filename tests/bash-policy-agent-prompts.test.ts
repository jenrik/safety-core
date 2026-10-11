import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const normalize = (text: string) => text.replace(/\s+/g, " ");
const author = normalize(readFileSync(resolve(root, ".opencode/agents/bash-policy-author.md"), "utf8"));
const reviewer = normalize(readFileSync(resolve(root, ".opencode/agents/bash-policy-adversarial-reviewer.md"), "utf8"));
const questionnaireReviewer = normalize(
  readFileSync(resolve(root, ".opencode/agents/bash-policy-questionnaire-reviewer.md"), "utf8"),
);

test("Bash policy author requires hermetic safety-core CLI evidence", () => {
  expect(author).toContain("safety-core validate");
  expect(author).toContain("safety-core explain --json --env-var NAME=VALUE -- '<bash-source>'");
  expect(author).toContain("--inherit-env");
  expect(author).toContain("--cwd");
  expect(author).toContain("--env-mode filtered");
  expect(author).toContain('env -i PATH="$PATH" safety-core --config /absolute/config.json');
  expect(author).not.toContain("SAFETY_CORE_CONFIG_HOME");
  expect(author).toContain("CLI evidence");
});

test("Bash policy reviewer requires independently verifiable CLI evidence", () => {
  expect(reviewer).toContain("bun src/cli.ts --config /absolute/config.json validate");
  expect(reviewer).toContain(
    "bun src/cli.ts --config /absolute/config.json explain --json --env-var NAME=VALUE -- '<bash-source>'",
  );
  expect(reviewer).toContain("--inherit-env");
  expect(reviewer).toContain("report the review as inconclusive");
  expect(reviewer).toContain('env -i PATH="$PATH" safety-core --config /absolute/config.json');
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

test("Bash policy author provides a scope-document template", () => {
  expect(author).toContain("## Scope Document Template");
  for (const section of [
    "## Intent",
    "## Tool identity and version",
    "## Protected action and asset",
    "## In scope",
    "## Out of scope and threat-model exclusions",
    "## Assumptions and non-goals",
    "## Expected outcomes",
  ]) {
    expect(author, section).toContain(section);
  }
  for (const outcome of ["**permit:**", "**defer:**", "**deny:**"]) {
    expect(author, outcome).toContain(outcome);
  }
  for (const phrase of [
    "upstream source code",
    "designed and tested against",
    "previous breaking release",
    "newer breaking release",
    "forward-compatibility posture",
    "shared scope document",
    "fixture checksum",
    "transparent wrappers are deconstructed",
    "hidden, preview, or otherwise unreviewed routes",
    "fails closed",
    "persistent side effect",
    "docs/known-bugs.md",
  ]) {
    expect(author, phrase).toContain(phrase);
  }
});

test("Bash policy author opens with DSL-derived scoping questions", () => {
  expect(author).toContain("## Scoping Questions");
  for (const question of [
    "upstream implementation",
    "basename",
    "selected-path",
    "isDirectExecutable",
    "environmentIndependent",
    "executionTargetIs",
    "hasInheritedExecutableFunction",
    "environmentIsKnown",
    "missingEnvironmentMayBePresent",
    "routing, credential, or configuration gates",
    "assignmentsAreSubset",
    "exact synonyms",
    "atEndOfArguments()",
    "statically known and non-empty",
    "restOfWord",
    "atEndOfWord()",
    "span",
    "modeled events",
    "equivalence classes",
    "future-work.md",
  ]) {
    expect(author, question).toContain(question);
  }
});

test("Bash policy author requires a co-located unit and property test suite", () => {
  expect(author).toContain("<policy_name>.test.ts");
  expect(author).toContain("unit tests and property tests");
  expect(author).toContain("policyTestForFile");
  expect(author).toContain("bun test");
  expect(author).toContain("safety-core test");
  expect(author).toContain("<policy_name>.policy.json");
  expect(author).toContain("<policy_name>.scope.md");
  expect(author).toContain("warning");
  expect(author).toContain("except the co-located `<policy_name>.test.ts`");
});

test("Bash policy reviewer remarks on missing tests but continues", () => {
  expect(reviewer).toContain("<policy_name>.test.ts");
  expect(reviewer).toContain("remark on it as a gap");
  expect(reviewer).toContain("continue the review");
});

test("property: author requires a co-located test suite for 1,024 policy names", () => {
  for (let seed = 0; seed < 1024; seed++) {
    const policyName = `policy-${seed.toString(36)}`;
    expect(author.replaceAll("<policy_name>", policyName), `seed ${seed}`).toContain(`${policyName}.test.ts`);
  }
});

test("Bash policy author invokes the questionnaire reviewer", () => {
  expect(author).toContain("bash-policy-questionnaire-reviewer");
});

test("Bash policy questionnaire reviewer is read-only and checks the questionnaire", () => {
  expect(questionnaireReviewer).toContain("mode: subagent");
  expect(questionnaireReviewer).toContain("hidden: true");
  expect(questionnaireReviewer).toContain('"*": deny');
  expect(questionnaireReviewer).toContain("read: allow");
  expect(questionnaireReviewer).toContain("Scoping Questions");
  expect(questionnaireReviewer).toContain("default scope assumptions");
  expect(questionnaireReviewer).toContain("<policy_name>.test.ts");
});

test("known-bugs and future-work record the wrapper and always-defer decisions", () => {
  const futureWork = normalize(readFileSync(resolve(root, "docs/future-work.md"), "utf8"));
  const knownBugs = normalize(readFileSync(resolve(root, "docs/known-bugs.md"), "utf8"));
  expect(futureWork).toContain("## Lint: a policy that can only ever defer");
  expect(knownBugs).toContain("## Transparent wrappers that the engine does not deconstruct");
});
