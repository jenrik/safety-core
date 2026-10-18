import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const manifestPath = resolve(import.meta.dir, "../.pre-commit-hooks.yaml");
const manifest = readFileSync(manifestPath, "utf8");
const config = readFileSync(resolve(import.meta.dir, "../.pre-commit-config.yaml"), "utf8");

function hookBlock(id: string): string {
  const block = manifest.split(/(?=^- id: )/m).find((candidate) => candidate.startsWith(`- id: ${id}\n`));
  if (block === undefined) throw new Error(`missing pre-commit hook: ${id}`);
  return block;
}

describe("published pre-commit hooks", () => {
  test("defines a filename-independent project-policy validation hook", () => {
    const hook = hookBlock("safety-core-validate-project-policies");

    expect(hook).toContain("entry: safety-core validate");
    expect(hook).toContain("language: node");
    expect(hook).toContain("pass_filenames: false");
    expect(hook).toContain("always_run: true");
  });

  test("defines a serial declarative-policy collection lint hook", () => {
    const hook = hookBlock("safety-core-lint-policy-collection");

    expect(hook).toContain("policy validate");
    expect(hook).toContain("language: node");
    expect(hook).toContain("require_serial: true");
  });

  test("installs the collection lint hook in this repository's pre-commit configuration", () => {
    expect(config).toContain("- id: safety-core-lint-policy-collection");
    expect(config).toContain("entry: >-");
    expect(config).toContain("safety-core policy validate");
    expect(config).toContain("language: system");
  });

  test("property: the collection hook selects only declarative policy filenames", () => {
    const hook = hookBlock("safety-core-lint-policy-collection");
    const files = hook.match(/^  files: (.+)$/m)?.[1];
    expect(files).toBeDefined();
    const policyFiles = new RegExp(files!);

    for (let seed = 0; seed < 1_024; seed++) {
      const stem = `policy-${seed.toString(36)}`;
      expect(policyFiles.test(`${stem}.policy.json`), `seed ${seed}`).toBe(true);
      expect(policyFiles.test(`${stem}.json`), `seed ${seed}`).toBe(false);
      expect(policyFiles.test(`${stem}.policy.mjs`), `seed ${seed}`).toBe(false);
      expect(policyFiles.test(`${stem}.policy.json.bak`), `seed ${seed}`).toBe(false);
    }
  });
});
