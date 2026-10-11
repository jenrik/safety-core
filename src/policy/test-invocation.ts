import { existsSync, realpathSync } from "node:fs";
import { PolicyStartupError } from "./config.js";

/** Filesystem operations needed to resolve a policy test invocation. */
export interface PolicyTestFilesystem {
  exists(path: string): boolean;
  realpath(path: string): string;
}

/** Default resolver backed by the real filesystem. */
export const nodePolicyTestFilesystem: PolicyTestFilesystem = Object.freeze({
  exists: (path: string): boolean => existsSync(path),
  realpath: (path: string): string => realpathSync(path),
});

/** A resolved policy test: the suite to run, its policy, and how it was requested. */
export interface PolicyTestInvocation {
  /** Canonical path the caller named: a test, policy, or scope document. */
  readonly requestedPath: string;
  /** Canonical path of the `.test.ts` suite to run. */
  readonly testPath: string;
  /** Canonical path of the policy under test. */
  readonly policyPath: string;
  /** True when the caller named a policy or scope document instead of the test file. */
  readonly aliased: boolean;
}

const TEST_EXTENSION = ".test.ts";
const SCOPE_EXTENSION = ".scope.md";
const POLICY_EXTENSION = ".policy";
const SOURCE_EXTENSIONS = [".json", ".mjs"] as const;

/**
 * Resolve the policy test suite for a requested path. A `.test.ts` suite is used
 * directly with its colocated policy. A `.json` or `.mjs` policy source or a
 * `.scope.md` document is accepted as an alias and resolves to the single
 * colocated `.test.ts` suite and its policy.
 */
export function resolvePolicyTestInvocation(
  requestedPath: string,
  filesystem: PolicyTestFilesystem = nodePolicyTestFilesystem,
): PolicyTestInvocation {
  const requested = canonical(requestedPath, filesystem);
  if (requested.endsWith(TEST_EXTENSION)) {
    const stem = requested.slice(0, -TEST_EXTENSION.length);
    return {
      requestedPath: requested,
      testPath: requested,
      policyPath: uniquePolicy(stem, requested, filesystem),
      aliased: false,
    };
  }
  if (requested.endsWith(SCOPE_EXTENSION)) {
    const base = requested.slice(0, -SCOPE_EXTENSION.length);
    const policyPath = uniquePolicy(base, requested, filesystem);
    return {
      requestedPath: requested,
      testPath: uniqueTest(policyStem(policyPath), requested, filesystem),
      policyPath,
      aliased: true,
    };
  }
  const sourceExtension = SOURCE_EXTENSIONS.find((extension) => requested.endsWith(extension));
  if (sourceExtension !== undefined) {
    const stem = requested.slice(0, -sourceExtension.length);
    return {
      requestedPath: requested,
      testPath: uniqueTest(stem, requested, filesystem),
      policyPath: requested,
      aliased: true,
    };
  }
  throw new PolicyStartupError(
    requested,
    "policy test source must be a .test.ts suite or a colocated policy or scope document",
  );
}

function canonical(path: string, filesystem: PolicyTestFilesystem): string {
  try {
    return filesystem.realpath(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot canonicalize policy test source", error);
  }
}

function policyStem(policyPath: string): string {
  const extension = SOURCE_EXTENSIONS.find((candidate) => policyPath.endsWith(candidate));
  return extension === undefined ? policyPath : policyPath.slice(0, -extension.length);
}

function policyCandidateNames(base: string): readonly string[] {
  return base.endsWith(POLICY_EXTENSION)
    ? [`${base}.json`, `${base}.mjs`]
    : [`${base}${POLICY_EXTENSION}.json`, `${base}${POLICY_EXTENSION}.mjs`, `${base}.json`, `${base}.mjs`];
}

function uniquePolicy(base: string, requested: string, filesystem: PolicyTestFilesystem): string {
  const names = policyCandidateNames(base);
  const candidates = names.filter((path) => filesystem.exists(path));
  if (candidates.length !== 1)
    throw new PolicyStartupError(
      requested,
      candidates.length === 0
        ? `cannot find policy under test; expected ${names[0]} or ${names[1]}`
        : "policy test is ambiguous; multiple colocated policies exist",
    );
  return canonical(candidates[0]!, filesystem);
}

function testCandidateNames(stem: string): readonly string[] {
  return stem.endsWith(POLICY_EXTENSION)
    ? [`${stem}${TEST_EXTENSION}`, `${stem.slice(0, -POLICY_EXTENSION.length)}${TEST_EXTENSION}`]
    : [`${stem}${TEST_EXTENSION}`];
}

function uniqueTest(stem: string, requested: string, filesystem: PolicyTestFilesystem): string {
  const names = testCandidateNames(stem);
  const candidates = names.filter((path) => filesystem.exists(path));
  if (candidates.length !== 1)
    throw new PolicyStartupError(
      requested,
      candidates.length === 0
        ? `cannot find colocated policy test; expected ${names.join(" or ")}`
        : "policy test is ambiguous; multiple colocated test suites exist",
    );
  return canonical(candidates[0]!, filesystem);
}
