import { afterEach, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const fixtures: string[] = [];

function fixture(): { readonly root: string; readonly testPath: string } {
  const root = mkdtempSync(join(tmpdir(), "safety-core-policy-testing-"));
  fixtures.push(root);
  const testPath = join(root, "example.policy.test.ts");
  writePolicy(join(root, "example.policy.mjs"), "example");
  writePolicy(join(root, "configured.policy.mjs"), "configured");
  writePolicy(join(root, "enabled.policy.mjs"), "enabled");
  writeFileSync(
    join(root, "config.json"),
    JSON.stringify({
      version: 1,
      policies: ["configured.policy.mjs"],
      projectPolicies: { mode: "disabled" },
      bashAnalysis: { maxFunctionDepth: 7, maxNestedScriptDepth: 6, maxSteps: 50, maxWorkItems: 50 },
    }),
  );
  writeFileSync(
    testPath,
    `import { expect } from "bun:test";

policyTest.test("unit setup selects configured and explicitly enabled policies", {
  config: "config.json",
  enabledPolicies: ["enabled.policy.mjs"],
  bashAnalysis: { maxSteps: 100 },
}, ({ evaluate, limits, policySet }) => {
  expect(limits.maxSteps).toBe(100);
  expect(policySet.sources).toHaveLength(3);
  expect(evaluate("example; configured; enabled").decision).toBe("allow");
});

policyTest.property("seeded properties preserve complete coverage", {
  config: "config.json",
  enabledPolicies: ["enabled.policy.mjs"],
  cases: 32,
  seed: 19,
}, ({ random, evaluate }) => {
  expect(evaluate(random.shuffle(["example", "configured", "enabled"]).join("; ")).decision).toBe("allow");
});
`,
  );
  return { root, testPath };
}

function writePolicy(path: string, executable: string): void {
  writeFileSync(
    path,
    `export default Object.freeze({
  apiVersion: 1,
  layer: "permission",
  select: Object.freeze([{ kind: "invocation", environmentIndependent: true }]),
  evaluate(event) {
    return event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "${executable}"
      ? { kind: "allow", reason: [{ kind: "literal", value: "${executable}" }] }
      : { kind: "ignore" };
  },
});
`,
  );
}

afterEach(() => {
  while (fixtures.length > 0) rmSync(fixtures.pop()!, { force: true, recursive: true });
});

describe("policy test runner", () => {
  test("runs unit and seeded property cases with test-local policy setup", () => {
    const { root, testPath } = fixture();
    const result = spawnSync("bun", [join(process.cwd(), "src/cli.ts"), "test", testPath], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env },
    });

    expect(result.status).toBe(0);
  }, 30_000);

  test("requires a colocated policy source with exactly one supported extension", () => {
    const { root, testPath } = fixture();
    rmSync(join(root, "example.policy.mjs"));
    const missing = spawnSync("bun", [join(process.cwd(), "src/cli.ts"), "test", testPath], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env },
    });
    expect(missing.status).not.toBe(0);
    expect(missing.stderr).toContain("cannot find policy under test");

    writePolicy(join(root, "example.policy.mjs"), "example");
    writeFileSync(join(root, "example.policy.json"), "{}");
    const ambiguous = spawnSync("bun", [join(process.cwd(), "src/cli.ts"), "test", testPath], {
      cwd: root,
      encoding: "utf8",
      env: { ...process.env },
    });
    expect(ambiguous.status).not.toBe(0);
    expect(ambiguous.stderr).toContain("policy test is ambiguous");
  }, 30_000);
});
