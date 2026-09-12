import { afterAll, beforeAll, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeBashAuthorization, initBashParser } from "../src/index.ts";
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
  ["function-depth", () => analyze(functionChain(DEFAULT_BASH_ANALYSIS_LIMITS.maxFunctionDepth + 1)).outcome],
  ["nested-script-depth", () => analyze(nestedSh()).outcome],
  ["steps", () => analyze(assignmentSequence(DEFAULT_BASH_ANALYSIS_LIMITS.maxSteps + 1)).outcome],
  ["work-items", () => exhaustWorkItems(DEFAULT_BASH_ANALYSIS_LIMITS.maxWorkItems + 1)],
])("calibrates %s cap exhaustion within the supported one-second guideline", (name, action) => {
  const measurement = measure(name, action);

  console.info(`Task 10 cap-exhaustion ${measurement.name}: ${measurement.milliseconds.toFixed(1)} ms`);
  expect(measurement.outcome).toMatchObject({ kind: "failure", reason: "analysis-failure" });
  expect(measurement.milliseconds).toBeLessThanOrEqual(1_000);
});

function analyze(source: string) {
  return analyzeBashAuthorization({ source, includeBaseHandlers: false });
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
