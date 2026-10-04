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

const timeoutPath = new URL("../policies/dsl/timeout.policy.json", import.meta.url);
const timeoutPolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(timeoutPath, "utf8"))),
  timeoutPath.pathname,
);

type TestWord =
  | { readonly kind: "known"; readonly value: string }
  | { readonly kind: "unknown"; readonly reason: { readonly kind: string } };

const known = (value: string): TestWord => ({ kind: "known", value });
const unknown = (): TestWord => ({ kind: "unknown", reason: { kind: "expansion" } });

beforeAll(async () => {
  await initBundledBashParser();
});

function timeoutDecision(argv: readonly TestWord[], overrides: Record<string, unknown> = {}): string {
  return timeoutPolicy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "timeout" },
    executionTarget: "external-path",
    executableIdentity: {
      qualification: "incomplete",
      spelling: "timeout",
      basename: "timeout",
      chain: [],
      failure: { kind: "not-found" },
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
    ...overrides,
  } as InvocationView).kind;
}

function analyze(source: string) {
  return analyzeBashWithPolicies({
    source,
    initialEnvironment: completePolicyInitialEnvironment({}),
    policies: [timeoutPolicy],
  });
}

function timeoutEvent(result: ReturnType<typeof analyze>): InvocationView {
  const event = result.events.find(
    (candidate): candidate is InvocationView =>
      candidate.kind === "invocation" &&
      candidate.executable?.kind === "known" &&
      candidate.executable.value === "timeout",
  );
  if (!event) throw new Error("missing timeout invocation");
  return event;
}

describe("timeout DSL policy", () => {
  test("permits direct GNU timeout forms while leaving the child to independent coverage", () => {
    for (const argv of [
      ["1s", "printf", "OK"],
      ["-vfp", "-k1.5m", "--signal=TERM", "0", "printf", "OK"],
      [
        "--kill-after",
        "1s",
        "--signal",
        "TERM",
        "--foreground",
        "--preserve-status",
        "--verbose",
        "1s",
        "printf",
        "OK",
      ],
      ["--", "-1s", "printf", "OK"],
      ["not-a-duration", "printf", "OK"],
    ]) {
      expect(timeoutDecision(argv.map(known)), argv.join(" ")).toBe("allow");
    }

    const result = analyze("timeout -v 1s printf OK");
    expect(timeoutPolicy.evaluate(timeoutEvent(result)).kind).toBe("allow");
    expect(
      result.events.flatMap((event) =>
        event.kind === "invocation" && event.executable?.kind === "known" ? [event.executable.value] : [],
      ),
    ).toEqual(["timeout", "printf"]);
    expect(result.decision).toBe("defer");
  });

  test("defers unrecognized, informational, incomplete, empty, and unresolved timeout operands", () => {
    for (const argv of [
      ["--unknown", "1s", "printf"],
      ["--verb", "1s", "printf"],
      ["--help", "1s", "printf"],
      ["--version", "1s", "printf"],
      ["1s"],
      ["", "printf"],
      ["1s", ""],
      ["-k", "", "1s", "printf"],
      ["--kill-after=", "1s", "printf"],
      ["-s", "", "1s", "printf"],
      ["--signal=", "1s", "printf"],
      ["-k", "1s"],
      ["-s", "TERM"],
    ]) {
      expect(timeoutDecision(argv.map(known)), argv.join(" ")).toBe("defer");
    }

    for (const argv of [
      [known("-k"), unknown(), known("1s"), known("printf")],
      [known("--signal"), unknown(), known("1s"), known("printf")],
    ]) {
      expect(timeoutDecision(argv)).toBe("defer");
    }
  });

  test("does not authorize a function shadowing timeout", () => {
    expect(timeoutDecision([known("1s"), known("printf")], { executionTarget: "shell-function" })).toBe("defer");
    const result = analyze("timeout() { :; }; timeout 1s printf OK");
    expect(result.events).toContainEqual(
      expect.objectContaining({
        kind: "invocation",
        executable: { kind: "known", value: "timeout" },
        executionTarget: "shell-function",
      }),
    );
  });

  test("property: documented short clusters and value forms preserve the wrapper boundary", () => {
    const clusters = new Set<string>();
    const visit = (prefix: string, remaining: readonly string[]) => {
      if (prefix) clusters.add(prefix);
      for (let index = 0; index < remaining.length; index++)
        visit(`${prefix}${remaining[index]!}`, [...remaining.slice(0, index), ...remaining.slice(index + 1)]);
    };
    visit("", ["f", "p", "v"]);

    for (const cluster of clusters) {
      expect(timeoutDecision([known(`-${cluster}`), known("1s"), known("printf")]), cluster).toBe("allow");
      for (const valueOption of ["k", "s"]) {
        const value = valueOption === "k" ? "1s" : "TERM";
        expect(timeoutDecision([known(`-${cluster}${valueOption}${value}`), known("1s"), known("printf")])).toBe(
          "allow",
        );
        expect(timeoutDecision([known(`-${cluster}${valueOption}`), known(value), known("1s"), known("printf")])).toBe(
          "allow",
        );
      }
    }
  });

  test("property: an unsafe kill-after or signal value cannot be repaired by later repeats", () => {
    const optionRuns = [["-v", "--signal=TERM"], ["-k1s"], ["-pv", "--kill-after=2s"]];
    const unsafeRuns: readonly (readonly TestWord[])[] = [
      [known("-k"), known("")],
      [known("--kill-after=")],
      [known("-s"), known("")],
      [known("--signal=")],
      [known("-k"), unknown()],
      [known("--signal"), unknown()],
    ];

    for (const unsafe of unsafeRuns) {
      for (let position = 0; position <= optionRuns.length; position++) {
        const argv = [
          ...optionRuns.slice(0, position).flat().map(known),
          ...unsafe,
          ...optionRuns.slice(position).flat().map(known),
          known("3s"),
          known("printf"),
        ];
        expect(
          timeoutDecision(argv),
          `${unsafe.map((word) => (word.kind === "known" ? word.value : "unknown")).join(" ")} at ${position}`,
        ).toBe("defer");
      }
    }
  });
});
