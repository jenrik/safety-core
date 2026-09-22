import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeBashWithPolicies, initBashParser, type BashPolicyEvent, type ValidatedBashPolicy } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-events-"));
const allow = Object.freeze({ kind: "allow" as const, reason: Object.freeze([{ kind: "literal" as const, value: "covered" }]) });
const deny = Object.freeze({ kind: "deny" as const, reason: Object.freeze([{ kind: "literal" as const, value: "denied" }]) });

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("Bash generic policy events", () => {
  test("retains exact modeled invocation data without redaction", () => {
    const result = analyzeBashWithPolicies({
      source: 'CANARY=exact-value gh "$UNKNOWN" > response.json',
      initialEnvironment: { kind: "unavailable" },
      policies: [policy("permission", () => allow)],
    });
    const event = onlyInvocation(result.events);

    expect(event.environment.CANARY).toEqual({ kind: "known", value: "exact-value" });
    expect(event.argv[0]).toEqual({ kind: "unknown", reason: expect.any(Object) });
    expect(event.redirects).toEqual([{ kind: "output", target: { kind: "known", value: "response.json" } }]);
    expect(event.assignments.CANARY).toEqual({ kind: "known", value: "exact-value" });
    expect(event.provenance).toEqual({ route: ["direct"] });
    expect(event.inPipeline).toBeFalse();
    expect(event.processEffect).toBe("none");
    expect(event.span).toEqual({ start: 0, end: 'CANARY=exact-value gh "$UNKNOWN" > response.json'.length });
    expect(Object.isFrozen(event)).toBeTrue();
    expect(Object.isFrozen(event.environment)).toBeTrue();
    expect(Object.isFrozen(event.assignments)).toBeTrue();
    expect(Object.isFrozen(event.assignments.CANARY)).toBeTrue();
    expect(() => { (event.assignments as Record<string, unknown>).CANARY = "mutated"; }).toThrow();
    expect(result.decision).toBe("defer");
  });

  test("retains core denials that occur before dispatch as an invocation event and request deny", () => {
    const result = analyzeBashWithPolicies({
      source: "gh < credentials.json",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(result.events)).toMatchObject({
      executable: { kind: "known", value: "gh" },
      redirects: [{ kind: "input", target: { kind: "known", value: "credentials.json" } }],
    });
    expect(result.decision).toBe("deny");
  });

  test("reports runner and walker budget cutoffs as execution gaps", () => {
    const runnerExhausted = analyzeBashWithPolicies({
      source: "gh one",
      initialEnvironment: { kind: "verified", values: {} },
      limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 0, maxWorkItems: 10 },
      policies: [policy("permission", () => allow)],
    });
    const walkerExhausted = analyzeBashWithPolicies({
      source: "gh one; gh two",
      initialEnvironment: { kind: "verified", values: {} },
      limits: { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 10, maxWorkItems: 1 },
      policies: [policy("permission", () => allow)],
    });

    expect(runnerExhausted.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "max-steps" }));
    expect(walkerExhausted.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "max-work-items" }));
    expect(runnerExhausted.decision).toBe("defer");
    expect(walkerExhausted.decision).toBe("defer");
  });

  test("retains absent-binding availability independently from materialized bindings", () => {
    const unavailable = analyzeBashWithPolicies({
      source: "gh status",
      initialEnvironment: { kind: "unavailable" },
      policies: [policy("permission", () => allow)],
    });
    const verified = analyzeBashWithPolicies({
      source: "gh status",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(unavailable.events).missingBindings).toBe("unknown");
    expect(onlyInvocation(verified.events).missingBindings).toBe("unset");
  });

  test("retains opaque children as gaps and does not hide a later deny", () => {
    const result = analyzeBashWithPolicies({
      source: "CANARY=gap-value exec --unknown opaque-canary; gh later",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [
        policy("permission", () => allow),
        policy("guard", (event) => event.kind === "invocation" && event.executable.kind === "known" && event.executable.value === "gh" ? deny : { kind: "ignore" }),
      ],
    });

    expect(result.events).toContainEqual(expect.objectContaining({
      kind: "execution-gap",
      reason: "structural-parse-failure",
      environment: { CANARY: { kind: "known", value: "gap-value" } },
      provenance: { route: ["direct"] },
      inPipeline: false,
      processEffect: "unknown",
      span: { start: 0, end: "CANARY=gap-value exec --unknown opaque-canary".length },
    }));
    expect(result.decision).toBe("deny");
  });

  test("retains pipeline context for every reachable pipeline invocation", () => {
    const result = analyzeBashWithPolicies({
      source: "printf value | gh status",
      initialEnvironment: { kind: "verified", values: {} },
      policies: [policy("permission", () => allow)],
    });

    expect(onlyInvocation(result.events)).toMatchObject({ inPipeline: true, processEffect: "none" });
  });

  test("property: deterministic repeated projection preserves every event field", () => {
    for (let index = 0; index < 64; index++) {
      const value = `value-${index}`;
      const result = analyzeBashWithPolicies({
        source: `env -i CANARY=${value} gh argument-${index}`,
        initialEnvironment: { kind: "verified", values: {} },
        policies: [policy("permission", () => allow)],
      });
      const event = result.events.find((candidate) => candidate.kind === "invocation" && candidate.executable.kind === "known" && candidate.executable.value === "gh");
      expect(event, String(index)).toMatchObject({
        environment: { CANARY: { kind: "known", value } },
        argv: [{ kind: "known", value: `argument-${index}` }],
        provenance: { route: ["direct", "transparent-wrapper"] },
        processEffect: "exec-replace",
      });
    }
  });
});

function policy(layer: "guard" | "permission", evaluate: (event: BashPolicyEvent) => ReturnType<ValidatedBashPolicy["evaluate"]>): ValidatedBashPolicy {
  return Object.freeze({
    source: Object.freeze({ canonicalPath: `/policies/${layer}.policy.mjs` }),
    layer,
    select: Object.freeze([]),
    evaluate,
  }) as ValidatedBashPolicy;
}

function onlyInvocation(events: readonly BashPolicyEvent[]) {
  const event = events.find((candidate) => candidate.kind === "invocation" && candidate.executable.kind === "known" && candidate.executable.value === "gh");
  if (!event || event.kind !== "invocation") throw new Error("Expected a gh invocation event");
  return event;
}
