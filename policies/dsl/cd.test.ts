import { expect } from "bun:test";

import { policyTestForFile } from "../../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

type Word = InvocationView["argv"][number];

const known = (value: string): Word => ({ kind: "known", value });

const unknownWord = (): Word => ({
  kind: "unknown",
  reason: { kind: "unknown-variable", span: { start: 0, end: 0 } },
});

function cdDecision(
  policy: ValidatedBashPolicy,
  executable: string,
  executionTarget: InvocationView["executionTarget"],
  argv: readonly Word[] = [],
  overrides: Record<string, unknown> = {},
): string {
  const basename = executable.split("/").filter(Boolean).at(-1) ?? executable;
  return policy.evaluate({
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
  } as any).kind;
}

policyTest.test("permits the direct cd builtin with any static or dynamic argument", ({ policy, evaluate }) => {
  for (const source of ["cd /tmp", "cd ..", "cd ~", "cd -", 'cd "/some dir"', 'cd "$HOME"', "cd"]) {
    expect(evaluate(source).decision, source).toBe("allow");
  }

  for (const argv of [
    [],
    [known("/tmp")],
    [unknownWord()],
    [known("--"), unknownWord(), known("x")],
    [known("-P"), known("/tmp")],
  ])
    expect(cdDecision(policy, "cd", "builtin", argv), JSON.stringify(argv)).toBe("allow");
});

policyTest.test("does not extend the permission to path-qualified cd spellings", ({ policy, evaluate }) => {
  for (const spelling of ["/bin/cd", "/usr/bin/cd", "./cd", "../cd"]) {
    expect(cdDecision(policy, spelling, "external-path", [known("/tmp")]), spelling).toBe("defer");
    expect(evaluate(`${spelling} /tmp`).decision, spelling).toBe("defer");
  }
});

policyTest.test("denies a definite shell-function shadowing cd", ({ policy, evaluate }) => {
  expect(cdDecision(policy, "cd", "shell-function", [known("/tmp")])).toBe("deny");

  const local = evaluate("cd() { :; }; cd /tmp");
  expect(local.decision).toBe("deny");
  expect(local.events).toContainEqual(
    expect.objectContaining({
      kind: "invocation",
      executable: { kind: "known", value: "cd" },
      executionTarget: "shell-function",
    }),
  );
});

policyTest.test("denies a known inherited executable function shadowing cd", ({ policy, evaluate }) => {
  expect(
    cdDecision(policy, "cd", "unresolved", [known("/tmp")], {
      environment: { __SAFETY_CORE_BASH_FUNCTION_cd: { kind: "known", value: "present" } },
    }),
  ).toBe("deny");
  expect(
    cdDecision(policy, "cd", "shell-function", [known("/tmp")], {
      environment: { __SAFETY_CORE_BASH_FUNCTION_cd: { kind: "known", value: "present" } },
    }),
  ).toBe("deny");

  const imported = evaluate("cd /tmp", {
    initialEnvironment: { kind: "verified", values: { "BASH_FUNC_cd%%": "() { :; }" } },
  });
  expect(imported.decision).toBe("deny");
});

policyTest.test(
  "defers command-prefix assignments and leaves redirect writes to the aggregate request",
  ({ policy, evaluate }) => {
    expect(evaluate("FOO=bar cd /tmp").decision).toBe("defer");
    expect(evaluate("cd /tmp > out").decision).toBe("defer");

    expect(
      cdDecision(policy, "cd", "builtin", [known("/tmp")], {
        assignments: { FOO: { kind: "known", value: "bar" } },
      }),
    ).toBe("defer");
    expect(
      cdDecision(policy, "cd", "builtin", [known("/tmp")], {
        redirects: [{ kind: "output", target: known("out") }],
      }),
    ).toBe("allow");
  },
);

policyTest.property(
  "direct cd allows arbitrary argv while path-qualified spellings always defer",
  { cases: 256, seed: 11 },
  ({ policy, random }) => {
    const pool = ["/tmp", "..", "~", "-", "-P", "some dir", "a;b", "--", "", "-L", "/"];
    const argv: Word[] = [];
    const length = random.integer(0, 6);
    for (let index = 0; index < length; index++) argv.push(random.boolean() ? known(random.pick(pool)) : unknownWord());

    expect(cdDecision(policy, "cd", "builtin", argv)).toBe("allow");

    const qualified = random.pick(["/bin/cd", "/usr/bin/cd", "./cd", "../cd"]);
    expect(cdDecision(policy, qualified, "external-path", argv)).toBe("defer");
  },
);
