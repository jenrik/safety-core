import { afterAll, beforeAll, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeBashAuthorization, initBashParser, parseBashProgram } from "../src/index.ts";
import { fromInitialEnvironment } from "../src/bash/environment.ts";
import { safe } from "../src/bash/outcome.ts";
import { DEFAULT_BASH_ANALYSIS_LIMITS, runSteps, type DispatchTarget } from "../src/bash/runner.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-performance-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

test.each([
  ["function-depth", "max-function-depth", () => analyze(functionChain(DEFAULT_BASH_ANALYSIS_LIMITS.maxFunctionDepth + 1)).outcome],
  ["nested-script-depth", "max-nested-script-depth", () => analyze(nestedSh()).outcome],
  ["steps", "max-steps", () => analyze(assignmentSequence(DEFAULT_BASH_ANALYSIS_LIMITS.maxSteps + 1)).outcome],
  ["work-items", "max-work-items", () => exhaustWorkItems(DEFAULT_BASH_ANALYSIS_LIMITS.maxWorkItems + 1)],
] as const)("calibrates %s cap exhaustion within the supported one-second guideline", (name, budget, action) => {
  const measurement = measure(name, action);

  console.info(`Task 10 cap-exhaustion ${measurement.name}: ${measurement.milliseconds.toFixed(1)} ms`);
  expect(measurement.outcome).toMatchObject({ kind: "failure", reason: "analysis-failure", budget });
  expect(measurement.milliseconds).toBeLessThanOrEqual(1_000);
});

test("reports the linear assignment-workload relationship used to calibrate maxSteps", () => {
  for (const maxSteps of [10_000, 15_000, 20_000, 25_000]) {
    const measurement = measure(`steps-${maxSteps}`, () => analyze(
      assignmentSequence(maxSteps + 1),
      { ...DEFAULT_BASH_ANALYSIS_LIMITS, maxSteps, maxWorkItems: maxSteps + 2 },
    ).outcome);
    console.info(`Task 10 assignment calibration ${maxSteps}: ${measurement.milliseconds.toFixed(1)} ms`);
    expect(measurement.outcome).toMatchObject({ kind: "failure", reason: "analysis-failure", budget: "max-steps" });
  }
});

test.each([
  ["sequential-conditionals", conditionalSequence(64)],
  ["conditional-loop", `while condition; do ${conditionalSequence(16)}; done`],
  ["short-circuit-chain", Array.from({ length: 64 }, (_, index) => `command-${index}`).join(" && ")],
] as const)("keeps the %s walker workload within the one-second guideline", (name, source) => {
  const measurement = measure(name, () => analyze(source).outcome);

  console.info(`Branch-heavy ${measurement.name}: ${measurement.milliseconds.toFixed(1)} ms`);
  expect(measurement.outcome).toMatchObject({ kind: "indeterminate" });
  expect(measurement.milliseconds).toBeLessThanOrEqual(1_000);
});

test("projects a long mixed short-circuit chain within the one-second guideline", () => {
  const source = Array.from({ length: 4_096 }, (_, index) => `command-${index}`)
    .map((command, index) => index === 0 ? command : `${index % 2 === 0 ? "&&" : "||"} ${command}`)
    .join(" ");
  const measurement = measure("mixed-short-circuit-projection", () => parseBashProgram(source));

  console.info(`Branch-heavy ${measurement.name}: ${measurement.milliseconds.toFixed(1)} ms`);
  expect(measurement.outcome).toMatchObject({ kind: "program" });
  expect(measurement.milliseconds).toBeLessThanOrEqual(1_000);
});

function analyze(source: string, limits = DEFAULT_BASH_ANALYSIS_LIMITS) {
  return analyzeBashAuthorization({ source, limits, includeBaseHandlers: false });
}

function functionChain(depth: number): string {
  const definitions = Array.from({ length: depth }, (_, index) => {
    const child = index + 1 < depth ? `f${index + 1}` : ":";
    return `f${index}(){ ${child}; }`;
  });
  return [...definitions, "f0"].join("; ");
}

function nestedSh(): string {
  return 'CHILD=\'sh -c "$CHILD"\'; export CHILD; sh -c "$CHILD"';
}

function assignmentSequence(length: number): string {
  return Array.from({ length }, (_, index) => `VALUE=${index}`).join("; ");
}

function conditionalSequence(length: number): string {
  return Array.from(
    { length },
    () => "if condition; then unknown-command; else unknown-command; fi",
  ).join("; ");
}

function exhaustWorkItems(length: number) {
  const state = fromInitialEnvironment();
  const target: DispatchTarget = Object.freeze({
    span: { start: 0, end: 0 },
    functionDepth: 0,
    nestedScriptDepth: 0,
    run: (received) => Object.freeze({ kind: "result" as const, state: received, outcome: safe(), span: { start: 0, end: 0 } }),
  });
  return runSteps(Object.freeze({
    kind: "fork" as const,
    state,
    targets: Object.freeze(Array.from({ length }, () => target)),
    span: { start: 0, end: 0 },
  })).outcome;
}

function measure(name: string, action: () => unknown) {
  const started = performance.now();
  const outcome = action();
  return Object.freeze({ name, outcome, milliseconds: performance.now() - started });
}
