import { describe, expect, test } from "bun:test";

import { evaluatePolicyEvents, validateLoadedBashPolicy } from "../src/policy/evaluate.ts";
import type {
  BashPolicyAnalysis,
  BashPolicyEvent,
  GuardBashPolicy,
  GuardPolicyDecision,
  PermissionBashPolicy,
  PolicyDecision,
  ValidatedBashPolicy,
} from "../src/policy/types.ts";
import { fromInitialEnvironment } from "../src/bash/environment.ts";

const allow = (reason: string) => ({ kind: "allow" as const, reason: literal(reason) });
const deny = (reason: string) => ({ kind: "deny" as const, reason: literal(reason) });
const defer = (reason: string) => ({ kind: "defer" as const, reason: literal(reason) });
const ignore = () => ({ kind: "ignore" as const });
const literal = (value: string) => [{ kind: "literal" as const, value }] as const;

const completeAnalysis = (): BashPolicyAnalysis => ({ complete: true });
const incompleteAnalysis = (): BashPolicyAnalysis => ({ complete: false });

function invocation(executable: string): BashPolicyEvent {
  return {
    kind: "invocation",
    executable: { kind: "known", value: executable },
    argv: Object.freeze([{ kind: "known", value: "--actual-argument" }]),
    environment: fromInitialEnvironment({ TOKEN: "actual-environment-value" }),
    span: { start: 0, end: executable.length },
  };
}

function executionGap(reason: string): BashPolicyEvent {
  return {
    kind: "execution-gap",
    reason,
    environment: fromInitialEnvironment({ TOKEN: "actual-environment-value" }),
    span: { start: 0, end: reason.length },
  };
}

function policy(
  canonicalPath: string,
  layer: "guard",
  evaluate: (event: BashPolicyEvent) => GuardPolicyDecision,
): GuardBashPolicy;
function policy(
  canonicalPath: string,
  layer: "permission",
  evaluate: (event: BashPolicyEvent) => PolicyDecision,
): PermissionBashPolicy;
function policy(
  canonicalPath: string,
  layer: ValidatedBashPolicy["layer"],
  evaluate: (event: BashPolicyEvent) => PolicyDecision,
): ValidatedBashPolicy {
  return {
    source: { canonicalPath },
    layer,
    select: [],
    evaluate,
  } as ValidatedBashPolicy;
}

function basename(event: BashPolicyEvent): string | undefined {
  return event.kind === "invocation" && event.executable?.kind === "known"
    ? event.executable.value
    : undefined;
}

describe("open Bash policy decision algebra", () => {
  test("allows only when separate permission policies cover every invocation", () => {
    expect(evaluatePolicyEvents([invocation("git"), invocation("docker")], [
      policy("/p/git", "permission", (event) => basename(event) === "git" ? allow("git read") : ignore()),
      policy("/p/docker", "permission", (event) => basename(event) === "docker" ? allow("docker read") : ignore()),
    ], completeAnalysis())).toMatchObject({ decision: "allow" });
  });

  test("a guard success cannot grant permission", () => {
    expect(evaluatePolicyEvents([invocation("git")], [
      policy("/p/guard", "guard", () => defer("guard passed")),
    ], completeAnalysis())).toMatchObject({ decision: "defer" });
  });

  test("defensively rejects a runtime guard allow as fatal", () => {
    expect(() => evaluatePolicyEvents([invocation("git")], [
      policy("/p/invalid-guard", "guard", (() => allow("invalid guard allow")) as unknown as (event: BashPolicyEvent) => GuardPolicyDecision),
    ], completeAnalysis())).toThrow("Guard policies cannot allow");
  });

  test("requires a canonical absolute source path without resolving source files", () => {
    for (const canonicalPath of ["relative/policy", "/p/../policy", "/p//policy", "/p/./policy"]) {
      expect(() => validateLoadedBashPolicy(policy(canonicalPath, "permission", () => allow("read"))), canonicalPath)
        .toThrow("canonical absolute path");
    }
    expect(validateLoadedBashPolicy(policy("/p/policy", "permission", () => allow("read"))).source)
      .toEqual({ canonicalPath: "/p/policy" });
  });

  test("any event denial wins over permission coverage", () => {
    expect(evaluatePolicyEvents([invocation("git"), invocation("docker")], [
      policy("/p/read", "permission", () => allow("read")),
      policy("/p/deny-docker", "guard", (event) => basename(event) === "docker" ? deny("docker denied") : ignore()),
    ], completeAnalysis())).toMatchObject({ decision: "deny" });
  });

  test("incomplete analysis and reachable execution gaps prevent whole-request allow", () => {
    const permissions = [policy("/p/read", "permission", () => allow("read"))];

    expect(evaluatePolicyEvents([invocation("git")], permissions, incompleteAnalysis())).toMatchObject({ decision: "defer" });
    expect(evaluatePolicyEvents([executionGap("opaque-child")], permissions, completeAnalysis())).toMatchObject({ decision: "defer" });
  });

  test("a policy may deny an execution gap", () => {
    expect(evaluatePolicyEvents([executionGap("opaque-child")], [
      policy("/p/gap", "guard", () => deny("opaque execution forbidden")),
    ], incompleteAnalysis())).toMatchObject({ decision: "deny" });
  });

  test("traces retain the original modeled argv and complete environment", () => {
    const event = invocation("git");
    const result = evaluatePolicyEvents([event], [policy("/p/read", "permission", () => allow("read"))], completeAnalysis());
    const trace = result.traces[0]!;

    expect(trace.event).toBe(event);
    if (event.kind !== "invocation") throw new Error("Expected an invocation event");
    expect(trace.event.kind === "invocation" && trace.event.argv).toBe(event.argv);
    expect(trace.event.environment).toBe(event.environment);
    expect(Object.isFrozen(result)).toBeTrue();
    expect(Object.isFrozen(result.traces)).toBeTrue();
    expect(Object.isFrozen(trace)).toBeTrue();
  });

  test("property: 1,024 deterministic policy and event order permutations preserve every aggregate", () => {
    const scenarios: ReadonlyArray<{
      readonly events: readonly BashPolicyEvent[];
      readonly policies: readonly ValidatedBashPolicy[];
      readonly expected: "allow" | "deny" | "defer";
    }> = [
      {
        events: [invocation("git"), invocation("docker")],
        policies: [
          policy("/p/git", "permission", (event) => basename(event) === "git" ? allow("git read") : ignore()),
          policy("/p/docker", "permission", (event) => basename(event) === "docker" ? allow("docker read") : ignore()),
        ],
        expected: "allow",
      },
      {
        events: [invocation("git"), invocation("docker"), executionGap("opaque-child")],
        policies: [
          policy("/p/git", "permission", (event) => basename(event) === "git" ? allow("git read") : ignore()),
          policy("/p/docker", "permission", (event) => basename(event) === "docker" ? allow("docker read") : ignore()),
          policy("/p/gap", "guard", (event) => event.kind === "execution-gap" ? deny("opaque execution forbidden") : ignore()),
        ],
        expected: "deny",
      },
      {
        events: [invocation("git"), invocation("docker")],
        policies: [policy("/p/git", "permission", (event) => basename(event) === "git" ? allow("git read") : ignore())],
        expected: "defer",
      },
    ];

    for (const [scenarioIndex, scenario] of scenarios.entries()) {
      expect(evaluatePolicyEvents(scenario.events, scenario.policies, completeAnalysis()).decision).toBe(scenario.expected);
      for (let seed = 0; seed < 1_024; seed++) {
        const eventOrder = permute(scenario.events, seed * 2 + 1);
        const policyOrder = permute(scenario.policies, seed * 2 + 2);
        expect(evaluatePolicyEvents(eventOrder, policyOrder, completeAnalysis()).decision, `scenario ${scenarioIndex}, seed ${seed}`)
          .toBe(scenario.expected);
      }
    }
  });
});

function permute<T>(values: readonly T[], seed: number): T[] {
  const result = [...values];
  let state = seed >>> 0;
  for (let index = result.length - 1; index > 0; index--) {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    const swap = state % (index + 1);
    [result[index], result[swap]] = [result[swap]!, result[index]!];
  }
  return result;
}
