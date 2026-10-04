import { beforeAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  analyzeBashWithPolicies,
  completePolicyInitialEnvironment,
  type InvocationView,
  initBundledBashParser,
} from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const sleepPath = new URL("../policies/dsl/sleep.policy.json", import.meta.url);
const sleepPolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(sleepPath, "utf8"))),
  sleepPath.pathname,
);

beforeAll(async () => {
  await initBundledBashParser();
});

function sleepDecision(
  executionTarget: InvocationView["executionTarget"],
  argv: InvocationView["argv"] = [],
  basename = "sleep",
): string {
  return sleepPolicy.evaluate({
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

describe("sleep DSL policy", () => {
  test("permits every non-function target and defers a definite Bash function", () => {
    for (const target of ["external-path", "builtin", "unresolved"] as const) {
      expect(sleepDecision(target), target).toBe("allow");
    }
    expect(sleepDecision("shell-function")).toBe("defer");
    expect(sleepDecision("external-path", [], "slepp")).toBe("ignore");
  });

  test("permits an unresolved sleep when the initial environment is unavailable", () => {
    const result = analyzeBashWithPolicies({
      source: "sleep 0",
      initialEnvironment: { kind: "unavailable" },
      policies: [sleepPolicy],
    });

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

  test("does not cover definite local or inherited sleep functions", () => {
    const result = analyzeBashWithPolicies({
      source: 'sleep() { /bin/sleep "$@"; }; sleep 0',
      initialEnvironment: completePolicyInitialEnvironment({}),
      policies: [sleepPolicy],
    });
    const functionEvent = result.events.find(
      (event): event is InvocationView =>
        event.kind === "invocation" &&
        event.executable?.kind === "known" &&
        event.executable.value === "sleep" &&
        event.executionTarget === "shell-function",
    );

    expect(functionEvent).toBeDefined();
    expect(functionEvent === undefined ? "ignore" : sleepPolicy.evaluate(functionEvent).kind).toBe("defer");
    expect(result.decision).toBe("defer");

    const inheritedResult = analyzeBashWithPolicies({
      source: "sleep 0",
      initialEnvironment: completePolicyInitialEnvironment({ "BASH_FUNC_sleep%%": '() { /bin/sleep "$@"; }' }),
      policies: [sleepPolicy],
    });
    const inheritedFunctionEvent = inheritedResult.events.find(
      (event): event is InvocationView =>
        event.kind === "invocation" &&
        event.executable?.kind === "known" &&
        event.executable.value === "sleep" &&
        event.executionTarget === "shell-function",
    );

    expect(inheritedFunctionEvent).toBeDefined();
    expect(inheritedFunctionEvent === undefined ? "ignore" : sleepPolicy.evaluate(inheritedFunctionEvent).kind).toBe(
      "defer",
    );
    expect(inheritedResult.decision).toBe("defer");
  });

  test("property: 64 arbitrary argv triples remain allowed", () => {
    const words = ["0", "--", "-2", ""] as const;
    for (let value = 0; value < 64; value++) {
      const argv = [0, 1, 2].map((position) => ({ kind: "known" as const, value: words[(value >> (position * 2)) & 3]! }));
      expect(sleepDecision("external-path", argv), argv.map((word) => JSON.stringify(word.value)).join(" ")).toBe(
        "allow",
      );
    }
  });

  test("permits unknown argv without inspecting it", () => {
    expect(
      sleepDecision("unresolved", [
        { kind: "unknown", reason: { kind: "unknown-variable", span: { start: 0, end: 0 } } },
        { kind: "known", value: "--help" },
      ]),
    ).toBe("allow");
  });
});
