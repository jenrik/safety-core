import { describe, expect, test } from "bun:test";

import type { BashFunction } from "../src/bash/cst.ts";
import { assignBinding, fromInitialEnvironment, known, lookupBinding } from "../src/bash/environment.ts";
import {
  completeShellState,
  defineShellFunction,
  forkShellState,
  initialShellState,
  joinShellStates,
  invalidateShellFunction,
  invalidateShellFunctions,
  removeShellFunction,
  withShellEnvironment,
} from "../src/bash/state.ts";

describe("complete abstract Bash shell state", () => {
  test("propagates every modeled domain from one current-scope child", () => {
    const parent = initialShellState(fromInitialEnvironment({ X: "outer" }));
    const definition = bashFunction("f");
    const child = defineShellFunction(withShellEnvironment(
      parent,
      assignBinding(parent.environment, "X", known("inner")),
    ), definition);

    const completed = completeShellState(parent, [{ state: child, writes: new Set(["X"]), scope: "current" }]);

    expect(lookupBinding(completed.environment, "X").value).toEqual({ kind: "known", value: "inner" });
    expect(completed.functionCandidates.get("f")).toEqual([definition]);
    expect(completed.missingFunctions.has("f")).toBeFalse();
  });

  test("discards every modeled domain from subshell children", () => {
    const parent = initialShellState(fromInitialEnvironment({ X: "outer" }));
    const child = defineShellFunction(withShellEnvironment(
      parent,
      assignBinding(parent.environment, "X", known("inner")),
    ), bashFunction("f"));

    expect(completeShellState(parent, [{ state: child, writes: new Set(["X"]), scope: "subshell" }])).toBe(parent);
  });

  test("property: branch ordering does not change conservative state joins", () => {
    const parent = initialShellState(fromInitialEnvironment({ X: "base" }));
    const leftDefinition = bashFunction("f", 1);
    const rightDefinition = bashFunction("f", 2);
    const branches = [
      {
        state: defineShellFunction(withShellEnvironment(parent, assignBinding(parent.environment, "X", known("left"))), leftDefinition),
        writes: new Set(["X"]),
      },
      {
        state: defineShellFunction(withShellEnvironment(parent, assignBinding(parent.environment, "X", known("right"))), rightDefinition),
        writes: new Set(["X"]),
      },
      { state: parent, writes: new Set<string>() },
    ];

    for (const ordered of permutations(branches)) {
      const joined = joinShellStates(forkShellState(parent), ordered);
      expect(lookupBinding(joined.environment, "X").value.kind).toBe("unknown");
      expect(new Set(joined.functionCandidates.get("f"))).toEqual(new Set([leftDefinition, rightDefinition]));
      expect(joined.missingFunctions.has("f")).toBeTrue();
    }
  });

  test("distinguishes definite function removal from conservative invalidation", () => {
    const definition = bashFunction("f");
    const initial = defineShellFunction(initialShellState(fromInitialEnvironment()), definition);
    const invalidated = invalidateShellFunction(initial, "f");
    const removed = removeShellFunction(initial, "f");

    expect(invalidated.functionCandidates.get("f")).toEqual([definition]);
    expect(invalidated.missingFunctions.has("f")).toBeTrue();
    expect(removed.functionCandidates.has("f")).toBeFalse();
    expect(removed.missingFunctions.has("f")).toBeTrue();
  });

  test("property: a dynamic function unset preserves every candidate as optional", () => {
    let state = initialShellState(fromInitialEnvironment());
    const names = Array.from({ length: 64 }, (_, index) => `f_${index}`);
    for (const name of names) state = defineShellFunction(state, bashFunction(name));

    const invalidated = invalidateShellFunctions(state);
    for (const name of names) {
      expect(invalidated.functionCandidates.has(name), name).toBeTrue();
      expect(invalidated.missingFunctions.has(name), name).toBeTrue();
    }
  });
});

function bashFunction(name: string, start = 0): BashFunction {
  return Object.freeze({
    kind: "function",
    name,
    body: Object.freeze({ kind: "group", statements: Object.freeze([]), span: Object.freeze({ start, end: start + 1 }) }),
    span: Object.freeze({ start, end: start + 1 }),
  });
}

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length <= 1) return [[...values]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)])
    .map((rest) => [value, ...rest]));
}
