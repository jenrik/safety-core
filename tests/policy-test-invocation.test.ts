import { describe, expect, test } from "bun:test";

import { type PolicyTestFilesystem, resolvePolicyTestInvocation } from "../src/policy/test-invocation.ts";

function memoryFilesystem(paths: readonly string[]): PolicyTestFilesystem {
  const present = new Set(paths);
  return {
    exists: (path: string): boolean => present.has(path),
    realpath: (path: string): string => {
      if (!present.has(path)) throw new Error(`ENOENT: ${path}`);
      return path;
    },
  };
}

describe("resolvePolicyTestInvocation", () => {
  test("runs a .test.ts suite directly with its colocated policy", () => {
    const filesystem = memoryFilesystem(["/p/find.test.ts", "/p/find.policy.json"]);
    expect(resolvePolicyTestInvocation("/p/find.test.ts", filesystem)).toEqual({
      requestedPath: "/p/find.test.ts",
      testPath: "/p/find.test.ts",
      policyPath: "/p/find.policy.json",
      aliased: false,
    });
  });

  test("also accepts the policy-suffixed test name directly", () => {
    const filesystem = memoryFilesystem(["/p/issues.policy.test.ts", "/p/issues.policy.json"]);
    expect(resolvePolicyTestInvocation("/p/issues.policy.test.ts", filesystem)).toEqual({
      requestedPath: "/p/issues.policy.test.ts",
      testPath: "/p/issues.policy.test.ts",
      policyPath: "/p/issues.policy.json",
      aliased: false,
    });
  });

  test("accepts a policy document as an alias and resolves its test", () => {
    const filesystem = memoryFilesystem(["/p/find.policy.json", "/p/find.test.ts"]);
    expect(resolvePolicyTestInvocation("/p/find.policy.json", filesystem)).toEqual({
      requestedPath: "/p/find.policy.json",
      testPath: "/p/find.test.ts",
      policyPath: "/p/find.policy.json",
      aliased: true,
    });
  });

  test("accepts a scope document as an alias and resolves its policy and test", () => {
    const filesystem = memoryFilesystem(["/p/issues.scope.md", "/p/issues.policy.json", "/p/issues.policy.test.ts"]);
    expect(resolvePolicyTestInvocation("/p/issues.scope.md", filesystem)).toEqual({
      requestedPath: "/p/issues.scope.md",
      testPath: "/p/issues.policy.test.ts",
      policyPath: "/p/issues.policy.json",
      aliased: true,
    });
  });

  test("rejects a missing policy, a missing test, ambiguity, and an unsupported extension", () => {
    expect(() => resolvePolicyTestInvocation("/p/find.test.ts", memoryFilesystem(["/p/find.test.ts"]))).toThrow(
      "cannot find policy under test",
    );
    expect(() => resolvePolicyTestInvocation("/p/find.policy.json", memoryFilesystem(["/p/find.policy.json"]))).toThrow(
      "cannot find colocated policy test",
    );
    expect(() =>
      resolvePolicyTestInvocation(
        "/p/find.policy.json",
        memoryFilesystem(["/p/find.policy.json", "/p/find.test.ts", "/p/find.policy.test.ts"]),
      ),
    ).toThrow("policy test is ambiguous");
    expect(() => resolvePolicyTestInvocation("/p/find.txt", memoryFilesystem(["/p/find.txt"]))).toThrow(
      "must be a .test.ts suite",
    );
  });
});

test("property: policy and scope aliases resolve the colocated suite for 1,024 names", () => {
  for (let seed = 0; seed < 1024; seed++) {
    const name = `policy-${seed.toString(36)}`;
    const policy = `/tmp/${name}.policy.json`;
    const test = `/tmp/${name}.test.ts`;
    const scope = `/tmp/${name}.scope.md`;
    const filesystem = memoryFilesystem([policy, test, scope]);

    const fromPolicy = resolvePolicyTestInvocation(policy, filesystem);
    const fromScope = resolvePolicyTestInvocation(scope, filesystem);
    const direct = resolvePolicyTestInvocation(test, filesystem);

    for (const invocation of [fromPolicy, fromScope, direct]) {
      expect(invocation.testPath, `seed ${seed}`).toBe(test);
      expect(invocation.policyPath, `seed ${seed}`).toBe(policy);
    }
    expect(fromPolicy.aliased, `seed ${seed}`).toBe(true);
    expect(fromScope.aliased, `seed ${seed}`).toBe(true);
    expect(direct.aliased, `seed ${seed}`).toBe(false);
  }
});
