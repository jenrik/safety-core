import { test as bunTest } from "bun:test";
import { existsSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { BashInitialEnvironment, BashPolicyEvaluation } from "../authorization.js";
import { analyzeBashWithPolicies } from "../authorization.js";
import { initBundledBashParser } from "../shell.js";
import { type BashAnalysisConfig, loadGlobalPolicyConfig, resolveSessionPolicyConfig } from "./config.js";
import { type ExecutableFilesystem, nodeExecutableFilesystem } from "./filesystem.js";
import { type LoadedPolicySet, loadPolicySet, loadPolicySources } from "./load.js";
import type { ValidatedBashPolicy } from "./types.js";

const defaultLimits: BashAnalysisConfig = Object.freeze({
  maxFunctionDepth: 128,
  maxNestedScriptDepth: 64,
  maxSteps: 7_500,
  maxWorkItems: 10_000,
});

export interface PolicyTestOptions {
  /** An authoritative global config. Relative paths are resolved from the test file. */
  readonly config?: string;
  /** Additional global policies to enable alongside the policy under test and configured policies. */
  readonly enabledPolicies?: readonly string[];
  /** Analysis limits when the test does not select a configuration file. */
  readonly bashAnalysis?: Partial<BashAnalysisConfig>;
  /** Working directory modeled for executable and path resolution. */
  readonly cwd?: string;
}

export interface PolicyTestEvaluationOptions {
  readonly initialEnvironment?: BashInitialEnvironment;
  readonly cwd?: string;
  readonly executableFilesystem?: ExecutableFilesystem;
}

export interface PolicyTestContext {
  readonly policyPath: string;
  /** The loaded policy under test, suitable for focused single-event unit tests. */
  readonly policy: ValidatedBashPolicy;
  readonly policySet: LoadedPolicySet;
  readonly limits: BashAnalysisConfig;
  evaluate(source: string, options?: PolicyTestEvaluationOptions): BashPolicyEvaluation;
}

export interface PolicyPropertyOptions extends PolicyTestOptions {
  /** Number of deterministic generated cases. Defaults to 100. */
  readonly cases?: number;
  /** Initial seed for the deterministic pseudo-random stream. Defaults to 1. */
  readonly seed?: number;
}

export interface PolicyPropertyCase extends PolicyTestContext {
  readonly index: number;
  readonly seed: number;
  readonly random: PolicyTestRandom;
}

export interface PolicyTestSuite {
  test(name: string, body: (context: PolicyTestContext) => unknown | Promise<unknown>): void;
  test(
    name: string,
    options: PolicyTestOptions,
    body: (context: PolicyTestContext) => unknown | Promise<unknown>,
  ): void;
  property(name: string, body: (sample: PolicyPropertyCase) => unknown | Promise<unknown>): void;
  property(
    name: string,
    options: PolicyPropertyOptions,
    body: (sample: PolicyPropertyCase) => unknown | Promise<unknown>,
  ): void;
}

/** Deterministic input generator for repeatable policy properties. */
export interface PolicyTestRandom {
  nextUint32(): number;
  integer(minimum: number, maximum: number): number;
  boolean(): boolean;
  pick<T>(values: readonly T[]): T;
  shuffle<T>(values: readonly T[]): T[];
}

/**
 * Create a Bun test suite that always enables the policy selected by
 * `safety-core test`, while allowing each case to select its own configuration
 * and supporting policies.
 */
export function createPolicyTestSuite(policyPath: string, testPath: string): PolicyTestSuite {
  const canonicalPolicyPath = canonicalPath(policyPath, "policy under test");
  const canonicalTestPath = canonicalPath(testPath, "policy test");
  const baseDirectory = dirname(canonicalTestPath);
  const test: PolicyTestSuite["test"] = (
    name: string,
    optionsOrBody: PolicyTestOptions | ((context: PolicyTestContext) => unknown | Promise<unknown>),
    maybeBody?: (context: PolicyTestContext) => unknown | Promise<unknown>,
  ) => {
    const { options, body } = testArguments(optionsOrBody, maybeBody);
    bunTest(name, async () => body(await createContext(canonicalPolicyPath, baseDirectory, options)));
  };
  const property: PolicyTestSuite["property"] = (
    name: string,
    optionsOrBody: PolicyPropertyOptions | ((sample: PolicyPropertyCase) => unknown | Promise<unknown>),
    maybeBody?: (sample: PolicyPropertyCase) => unknown | Promise<unknown>,
  ) => {
    const { options, body } = propertyArguments(optionsOrBody, maybeBody);
    const cases = options.cases ?? 100;
    const initialSeed = options.seed ?? 1;
    if (!Number.isSafeInteger(cases) || cases <= 0)
      throw new TypeError("property cases must be a positive safe integer");
    if (!Number.isSafeInteger(initialSeed)) throw new TypeError("property seed must be a safe integer");
    bunTest(name, async () => {
      const context = await createContext(canonicalPolicyPath, baseDirectory, options);
      for (let index = 0; index < cases; index++) {
        const seed = (initialSeed + index) >>> 0;
        await body(Object.freeze({ ...context, index, seed, random: createRandom(seed) }));
      }
    });
  };

  return Object.freeze({ test, property });
}

/** Create a suite from the environment installed by `safety-core test`. */
export function policyTestFromEnvironment(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): PolicyTestSuite {
  const policyPath = environment.SAFETY_CORE_POLICY_TEST_POLICY;
  const testPath = environment.SAFETY_CORE_POLICY_TEST_FILE;
  if (policyPath === undefined || testPath === undefined) {
    throw new Error("policy tests must be started with safety-core test <policy>.test.ts");
  }
  return createPolicyTestSuite(policyPath, testPath);
}

/**
 * Create a colocated suite from a test module URL. This works under plain Bun
 * discovery and uses the CLI-selected paths when started through safety-core.
 */
export function policyTestForFile(testUrl: string): PolicyTestSuite {
  const testPath = canonicalPath(fileURLToPath(testUrl), "policy test");
  const selectedTestPath = process.env.SAFETY_CORE_POLICY_TEST_FILE;
  if (selectedTestPath !== undefined && canonicalPath(selectedTestPath, "policy test") === testPath) {
    return policyTestFromEnvironment();
  }
  const stem = testPath.slice(0, -".test.ts".length);
  const candidates = [".policy.json", ".policy.mjs", ".json", ".mjs"]
    .map((extension) => `${stem}${extension}`)
    .filter(existsSync);
  if (candidates.length !== 1) {
    throw new Error(`${testPath}: expected exactly one colocated policy source`);
  }
  return createPolicyTestSuite(candidates[0]!, testPath);
}

async function createContext(
  policyPath: string,
  baseDirectory: string,
  options: PolicyTestOptions,
): Promise<PolicyTestContext> {
  const cwd = options.cwd === undefined ? baseDirectory : resolvePath(baseDirectory, options.cwd);
  const configured = await loadConfiguredPolicies(baseDirectory, cwd, options.config);
  const enabled = options.enabledPolicies ?? [];
  const policySet = await loadPolicySources([
    { path: policyPath, scope: "global" },
    ...configured.policySet.sources.map((source) => ({ path: source.canonicalPath, scope: source.scope })),
    ...enabled.map((path) => ({ path: resolvePath(baseDirectory, path), scope: "global" as const })),
  ]);
  const limits = mergeLimits(configured.limits, options.bashAnalysis);
  const policy = policySet.policies.find((candidate) => candidate.source.canonicalPath === policyPath);
  if (policy === undefined) throw new Error(`${policyPath}: policy under test was not loaded`);
  await initBundledBashParser();

  return Object.freeze({
    policyPath,
    policy,
    policySet,
    limits,
    evaluate(source: string, evaluationOptions: PolicyTestEvaluationOptions = {}) {
      return analyzeBashWithPolicies({
        source,
        limits,
        policies: policySet.policies,
        initialEnvironment: evaluationOptions.initialEnvironment ?? { kind: "verified", values: {} },
        cwd: evaluationOptions.cwd ?? cwd,
        executableFilesystem: evaluationOptions.executableFilesystem ?? nodeExecutableFilesystem,
      });
    },
  });
}

async function loadConfiguredPolicies(
  baseDirectory: string,
  cwd: string,
  configPath: string | undefined,
): Promise<{ readonly policySet: LoadedPolicySet; readonly limits: BashAnalysisConfig }> {
  if (configPath === undefined) return Object.freeze({ policySet: await loadPolicySources([]), limits: defaultLimits });
  const config = loadGlobalPolicyConfig({}, resolvePath(baseDirectory, configPath));
  const resolved = resolveSessionPolicyConfig(config, cwd);
  return Object.freeze({ policySet: await loadPolicySet(resolved), limits: config.bashAnalysis });
}

function mergeLimits(base: BashAnalysisConfig, patch: Partial<BashAnalysisConfig> | undefined): BashAnalysisConfig {
  const limits = { ...base, ...patch };
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0)
      throw new TypeError(`bashAnalysis.${name} must be a positive safe integer`);
  }
  return Object.freeze(limits);
}

function testArguments(
  optionsOrBody: PolicyTestOptions | ((context: PolicyTestContext) => unknown | Promise<unknown>),
  maybeBody: ((context: PolicyTestContext) => unknown | Promise<unknown>) | undefined,
): { readonly options: PolicyTestOptions; readonly body: (context: PolicyTestContext) => unknown | Promise<unknown> } {
  if (typeof optionsOrBody === "function") return { options: {}, body: optionsOrBody };
  if (maybeBody === undefined) throw new TypeError("policy test body is required");
  return { options: optionsOrBody, body: maybeBody };
}

function propertyArguments(
  optionsOrBody: PolicyPropertyOptions | ((sample: PolicyPropertyCase) => unknown | Promise<unknown>),
  maybeBody: ((sample: PolicyPropertyCase) => unknown | Promise<unknown>) | undefined,
): {
  readonly options: PolicyPropertyOptions;
  readonly body: (sample: PolicyPropertyCase) => unknown | Promise<unknown>;
} {
  if (typeof optionsOrBody === "function") return { options: {}, body: optionsOrBody };
  if (maybeBody === undefined) throw new TypeError("policy property body is required");
  return { options: optionsOrBody, body: maybeBody };
}

function resolvePath(baseDirectory: string, path: string): string {
  return isAbsolute(path) ? path : resolve(baseDirectory, path);
}

function canonicalPath(path: string, subject: string): string {
  try {
    return realpathSync(path);
  } catch (error) {
    throw new Error(`${path}: cannot canonicalize ${subject}`, { cause: error });
  }
}

function createRandom(seed: number): PolicyTestRandom {
  let state = seed >>> 0;
  const nextUint32 = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return (value ^ (value >>> 14)) >>> 0;
  };
  const random: PolicyTestRandom = {
    nextUint32,
    integer(minimum: number, maximum: number) {
      if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum > maximum) {
        throw new RangeError("integer bounds must be ordered safe integers");
      }
      const width = maximum - minimum + 1;
      if (!Number.isSafeInteger(width) || width > 0x1_0000_0000) throw new RangeError("integer range is too large");
      return minimum + (nextUint32() % width);
    },
    boolean() {
      return (nextUint32() & 1) === 1;
    },
    pick<T>(values: readonly T[]): T {
      if (values.length === 0) throw new RangeError("cannot pick from an empty array");
      return values[nextUint32() % values.length]!;
    },
    shuffle<T>(values: readonly T[]): T[] {
      const result = [...values];
      for (let index = result.length - 1; index > 0; index--) {
        const swap = nextUint32() % (index + 1);
        [result[index], result[swap]] = [result[swap]!, result[index]!];
      }
      return result;
    },
  };
  return Object.freeze(random);
}
