import { describe, expect, test } from "bun:test";
import { BASH_FUNCTIONS_CAPTURED_FACT, inheritedBashFunctionFact } from "../src/bash/policy-environment.ts";
import { buildExplainEnvironment, type ExplainEnvironmentAssignment } from "../src/policy/explain.ts";

const assignment = (name: string, value: string): ExplainEnvironmentAssignment => Object.freeze({ name, value });

describe("buildExplainEnvironment", () => {
  test("an empty input is a verified, hermetic environment that proves names unset", () => {
    const environment = buildExplainEnvironment();
    expect(environment.kind).toBe("verified");
    if (environment.kind !== "verified") throw new Error("expected verified");
    expect(Object.keys(environment.values)).toEqual([BASH_FUNCTIONS_CAPTURED_FACT]);
  });

  test("assignments become exact known values and remain hermetic without --inherit-env", () => {
    const environment = buildExplainEnvironment({
      assignments: [assignment("CANARY", "exact-value")],
      ambient: { AMBIENT_ONLY: "leaked" },
    });
    expect(environment.kind).toBe("verified");
    if (environment.kind !== "verified") throw new Error("expected verified");
    expect(environment.values.CANARY).toBe("exact-value");
    expect(environment.values.AMBIENT_ONLY).toBeUndefined();
  });

  test("--inherit-env captures ambient values and --env-var overrides them", () => {
    const environment = buildExplainEnvironment({
      inheritEnv: true,
      ambient: { AMBIENT: "from-ambient", OVERRIDDEN: "old" },
      assignments: [assignment("OVERRIDDEN", "new")],
    });
    expect(environment.kind).toBe("verified");
    if (environment.kind !== "verified") throw new Error("expected verified");
    expect(environment.values.AMBIENT).toBe("from-ambient");
    expect(environment.values.OVERRIDDEN).toBe("new");
  });

  test("filtered mode keeps supplied values but treats unspecified names as unknown", () => {
    const environment = buildExplainEnvironment({
      mode: "filtered",
      assignments: [assignment("CANARY", "exact-value")],
    });
    expect(environment).toMatchObject({ kind: "filtered", unset: [], values: { CANARY: "exact-value" } });
  });

  test("injects the exported-function shadow fact used by the harness adapters", () => {
    const environment = buildExplainEnvironment({
      assignments: [assignment("BASH_FUNC_canary%%", "() { :; }")],
    });
    if (environment.kind !== "verified") throw new Error("expected verified");
    expect(environment.values[inheritedBashFunctionFact("canary")]).toBeDefined();
  });

  test("property: ambient values never leak unless --inherit-env is set", () => {
    const random = lcg(0x5eed);
    for (let seed = 0; seed < 1_024; seed++) {
      const ambient: Record<string, string> = {};
      const names = uniqueNames(random);
      for (const name of names) ambient[name] = `ambient-${seed}`;
      const assignments = names.slice(0, names.length >> 1).map((name) => assignment(name, `assigned-${seed}`));
      const inherited = buildExplainEnvironment({ assignments, ambient, inheritEnv: true });
      const hermetic = buildExplainEnvironment({ assignments });
      if (inherited.kind !== "verified" || hermetic.kind !== "verified") throw new Error("expected verified");
      for (const assignmentValue of assignments) {
        expect(inherited.values[assignmentValue.name], `seed ${seed}`).toBe(assignmentValue.value);
        expect(hermetic.values[assignmentValue.name], `seed ${seed}`).toBe(assignmentValue.value);
      }
      const assignedNames = new Set(assignments.map((value) => value.name));
      for (const name of names) {
        if (assignedNames.has(name)) continue;
        expect(inherited.values[name], `seed ${seed}`).toBe(`ambient-${seed}`);
        expect(hermetic.values[name], `seed ${seed}`).toBeUndefined();
      }
    }
  });

  test("property: the last assignment for a name wins and mode selects the snapshot semantics", () => {
    const random = lcg(0xc0ffee);
    for (let seed = 0; seed < 1_024; seed++) {
      const name = `VAR_${seed}`;
      const count = 1 + (random.nextInt(0, 4) as number);
      const assignments = Array.from({ length: count }, (_, index) => assignment(name, `v${index}`));
      const verified = buildExplainEnvironment({ assignments, mode: "verified" });
      const filtered = buildExplainEnvironment({ assignments, mode: "filtered" });
      if (verified.kind !== "verified" || filtered.kind !== "filtered") throw new Error("unexpected kind");
      expect(verified.values[name], `seed ${seed}`).toBe(`v${count - 1}`);
      expect(filtered.values[name], `seed ${seed}`).toBe(`v${count - 1}`);
      expect(filtered.unset, `seed ${seed}`).toHaveLength(0);
    }
  });
});

function uniqueNames(random: ReturnType<typeof lcg>): string[] {
  const count = 1 + (random.nextInt(0, 6) as number);
  const names = new Set<string>();
  while (names.size < count) names.add(`VAR_${random.nextInt(0, 64)}`);
  return [...names];
}

function lcg(seed: number): { nextInt(min: number, max: number): number } {
  let state = seed >>> 0;
  const next = () => {
    state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
    return state;
  };
  return {
    nextInt(min: number, max: number): number {
      return min + (next() % (max - min + 1));
    },
  };
}
