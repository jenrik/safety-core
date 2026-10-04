import { expect } from "bun:test";

import { policyTestForFile } from "../../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

function sleepDecision(
  policy: ValidatedBashPolicy,
  executionTarget: InvocationView["executionTarget"],
  argv: InvocationView["argv"] = [],
  basename = "sleep",
): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: basename },
    executionTarget,
    executableIdentity: {
      qualification: "incomplete",
      spelling: basename,
      basename,
      chain: [],
      failure: { kind: "not-external" },
    },
    argv,
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  }).kind;
}

policyTest.test("permits every non-function target and defers a definite Bash function", ({ policy }) => {
  for (const target of ["external-path", "builtin", "unresolved"] as const) {
    expect(sleepDecision(policy, target), target).toBe("allow");
  }
  expect(sleepDecision(policy, "shell-function")).toBe("defer");
  expect(sleepDecision(policy, "external-path", [], "slepp")).toBe("ignore");
});

policyTest.test("permits an unresolved sleep when the initial environment is unavailable", ({ evaluate }) => {
  const result = evaluate("sleep 0", { initialEnvironment: { kind: "unavailable" } });

  expect(result.decision).toBe("allow");
  expect(result.events).toContainEqual(
    expect.objectContaining({
      kind: "invocation",
      executable: { kind: "known", value: "sleep" },
      executionTarget: "unresolved",
      missingBindings: "unknown",
    }),
  );
});

policyTest.test("does not cover definite local or inherited sleep functions", ({ policy, evaluate }) => {
  const result = evaluate('sleep() { /bin/sleep "$@"; }; sleep 0');
  const functionEvent = result.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === "sleep" &&
      event.executionTarget === "shell-function",
  );

  expect(functionEvent).toBeDefined();
  expect(functionEvent === undefined ? "ignore" : policy.evaluate(functionEvent).kind).toBe("defer");
  expect(result.decision).toBe("defer");

  const inheritedResult = evaluate("sleep 0", {
    initialEnvironment: { kind: "verified", values: { "BASH_FUNC_sleep%%": '() { /bin/sleep "$@"; }' } },
  });
  const inheritedFunctionEvent = inheritedResult.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === "sleep" &&
      event.executionTarget === "shell-function",
  );

  expect(inheritedFunctionEvent).toBeDefined();
  expect(inheritedFunctionEvent === undefined ? "ignore" : policy.evaluate(inheritedFunctionEvent).kind).toBe("defer");
  expect(inheritedResult.decision).toBe("defer");
});

policyTest.property("arbitrary argv triples remain allowed", { cases: 64, seed: 1 }, ({ policy, random }) => {
  const words = ["0", "--", "-2", ""] as const;
  const argv = Array.from({ length: 3 }, () => ({ kind: "known" as const, value: random.pick(words) }));
  expect(sleepDecision(policy, "external-path", argv), argv.map((word) => JSON.stringify(word.value)).join(" ")).toBe("allow");
});

policyTest.test("permits unknown argv without inspecting it", ({ policy }) => {
  expect(
    sleepDecision(policy, "unresolved", [
      { kind: "unknown", reason: { kind: "unknown-variable", span: { start: 0, end: 0 } } },
      { kind: "known", value: "--help" },
    ]),
  ).toBe("allow");
});
