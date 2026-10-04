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

const teePath = new URL("../policies/dsl/tee.policy.json", import.meta.url);
const teePolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(teePath, "utf8"))),
  teePath.pathname,
);

beforeAll(async () => {
  await initBundledBashParser();
});

function decision(
  executable: string,
  executionTarget: InvocationView["executionTarget"],
  argv: readonly string[] = [],
): string {
  const basename = executable.split("/").filter(Boolean).at(-1) ?? "";
  return teePolicy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: executable },
    executionTarget,
    executableIdentity: {
      qualification: "incomplete",
      spelling: executable,
      basename,
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: argv.map((value) => ({ kind: "known" as const, value })),
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

function analyze(source: string, environment: Record<string, string> = {}) {
  return analyzeBashWithPolicies({
    source,
    initialEnvironment: completePolicyInitialEnvironment(environment),
    policies: [teePolicy],
  });
}

function externalTee(result: ReturnType<typeof analyze>): InvocationView {
  const event = result.events.find(
    (candidate): candidate is InvocationView =>
      candidate.kind === "invocation" &&
      candidate.executable?.kind === "known" &&
      candidate.executable.value === "tee" &&
      candidate.executionTarget === "external-path",
  );
  if (!event) throw new Error("missing external tee invocation");
  return event;
}

describe("tee DSL policy", () => {
  test("permits external tee basename spellings with arbitrary operands", () => {
    for (const [executable, argv] of [
      ["tee", []],
      ["tee", ["output.txt"]],
      ["tee", ["--append", "--output-error=warn", "--", "-literal-name"]],
      ["tee", ["-aip", "/tmp/one", "/tmp/two"]],
      ["/usr/bin/tee", ["/etc/arbitrary-output"]],
    ] as const)
      expect(decision(executable, "external-path", argv), `${executable} ${argv.join(" ")}`).toBe("allow");
  });

  test("permits an unresolved operand when lookup proves an external-path target", () => {
    const result = teePolicy.evaluate({
      kind: "invocation",
      executable: { kind: "known", value: "tee" },
      executionTarget: "external-path",
      executableIdentity: {
        qualification: "incomplete",
        spelling: "tee",
        basename: "tee",
        chain: [],
        failure: { kind: "not-found" },
      },
      argv: [{ kind: "unknown", reason: { kind: "unknown-variable", span: { start: 0, end: 0 } } }],
      environment: {},
      missingBindings: "unset",
      redirects: [],
      assignments: {},
      span: { start: 0, end: 0 },
      provenance: { route: ["direct"] },
      inPipeline: false,
      processEffect: "none",
    } as InvocationView);
    expect(result.kind).toBe("allow");
  });

  test("defers function and other non-external targets and ignores other basenames", () => {
    for (const target of ["builtin", "shell-function", "unresolved"] as const)
      expect(decision("tee", target), target).toBe("defer");
    for (const executable of ["gtee", "teed", "tee.exe", "/usr/bin/tee-copy"])
      expect(decision(executable, "external-path"), executable).toBe("ignore");
  });

  test("defers local and inherited tee functions before their bodies", () => {
    for (const [source, environment] of [
      ["tee() { :; }; tee output.txt", {}],
      ["tee output.txt", { "BASH_FUNC_tee%%": "() { :; }" }],
    ] as const) {
      const result = analyze(source, environment);
      expect(result.decision, source).toBe("defer");
      expect(result.events).toContainEqual(
        expect.objectContaining({
          kind: "invocation",
          executable: { kind: "known", value: "tee" },
          executionTarget: "shell-function",
        }),
      );
    }
  });

  test("models command before its permitted nested tee invocation", () => {
    const result = analyze("command tee --append output.txt");
    expect(
      result.events.flatMap((event) =>
        event.kind === "invocation" && event.executable?.kind === "known" ? [event.executable.value] : [],
      ),
    ).toEqual(["command", "tee"]);
    expect(teePolicy.evaluate(externalTee(result)).kind).toBe("allow");
    expect(result.decision).toBe("defer");
  });

  test("property: arbitrary argument sequences do not change an external tee decision", () => {
    const words = ["", "--", "-a", "--output-error=warn", "output.txt", "/tmp/output", "$(unknown)"];
    let state = 0x9e3779b9;
    for (let seed = 0; seed < 256; seed++) {
      const argv = Array.from({ length: state % 8 }, () => {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        return words[state % words.length]!;
      });
      expect(
        decision(seed % 2 === 0 ? "tee" : "/nix/store/coreutils/bin/tee", "external-path", argv),
        `seed ${seed}`,
      ).toBe("allow");
    }
  });
});
