import { expect } from "bun:test";
import { fileURLToPath } from "node:url";

import { completePolicyInitialEnvironment } from "../src/index.ts";
import { createPolicyTestSuite } from "../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../src/policy/types.ts";

const policyPath = fileURLToPath(new URL("./bun-run.policy.json", import.meta.url));
const policyTest = createPolicyTestSuite(policyPath, fileURLToPath(import.meta.url));

/** The reviewed package.json script allowlist this project policy owns. */
const reviewedScripts = ["build:native-packages", "test", "typescheck"] as const;

const environment = completePolicyInitialEnvironment({ PATH: "/usr/bin:/bin" });

function invocation(
  executable: string,
  executionTarget: InvocationView["executionTarget"],
  argv: readonly string[],
): InvocationView {
  const basename = executable.split("/").filter(Boolean).at(-1) ?? "";
  return {
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
  };
}

function decision(
  policy: ValidatedBashPolicy,
  executable: string,
  executionTarget: InvocationView["executionTarget"],
  argv: readonly string[] = [],
): string {
  return policy.evaluate(invocation(executable, executionTarget, argv)).kind;
}

policyTest.test("permits the explicit run subcommand for every reviewed script", ({ policy }) => {
  for (const script of reviewedScripts)
    expect(decision(policy, "bun", "external-path", ["run", script]), `bun run ${script}`).toBe("allow");
});

policyTest.test("defers every other script name, spelling, and argument position", ({ policy }) => {
  for (const argv of [
    [],
    ["run"],
    ["run", "lint"],
    ["run", "build"],
    ["run", "build:native-packages-extra"],
    ["run", "./scripts/build-native-node-packages.ts"],
    ["run", "scripts/build-bash-grammar.ts"],
    ["run", "--silent", "test"],
    ["run", "test", "--silent"],
    ["run", "test", "tests/example.test.ts"],
    ["run", "test", "extra"],
    ["typescheck"],
    ["test"],
    ["test", "tests/example.test.ts"],
    ["--run", "test"],
    ["run", ""],
  ])
    expect(decision(policy, "bun", "external-path", argv), `bun ${argv.join(" ")}`).toBe("defer");
});

policyTest.test("requires an unqualified direct spelling and an external-path target", ({ policy }) => {
  for (const executable of ["/usr/bin/bun", "./bun", "bunx", "node"])
    expect(decision(policy, executable, "external-path", ["run", "test"]), executable).toBe(
      executable === "bunx" || executable === "node" ? "ignore" : "defer",
    );
  for (const target of ["builtin", "shell-function", "unresolved"] as const)
    expect(decision(policy, "bun", target, ["run", "test"]), target).toBe("defer");
});

policyTest.test("permits the reviewed dev-loop invocations modeled from source", ({ evaluate }) => {
  for (const script of reviewedScripts) {
    const source = `bun run ${script}`;
    const result = evaluate(source, { initialEnvironment: environment });
    expect(result.decision, source).toBe("allow");
    const [event] = result.events;
    expect(event).toMatchObject({
      kind: "invocation",
      executable: { kind: "known", value: "bun" },
      executionTarget: "external-path",
    });
    expect(
      event?.kind === "invocation" ? event.argv.map((word) => (word.kind === "known" ? word.value : "<unknown>")) : [],
    ).toEqual(["run", script]);
  }
});

policyTest.test("defers prefix assignments, function shadowing, and wrapped invocations", ({ evaluate, policy }) => {
  expect(evaluate("FOO=1 bun run test", { initialEnvironment: environment }).decision).toBe("defer");

  const local = evaluate("bun() { :; }; bun run test", { initialEnvironment: environment });
  expect(local.decision).toBe("defer");
  expect(local.events).toContainEqual(
    expect.objectContaining({ kind: "invocation", executionTarget: "shell-function" }),
  );

  const imported = evaluate("bun run test", {
    initialEnvironment: completePolicyInitialEnvironment({ PATH: "/usr/bin:/bin", "BASH_FUNC_bun%%": "() { :; }" }),
  });
  expect(imported.decision).toBe("defer");

  const wrapped = evaluate("command bun run test", { initialEnvironment: environment });
  expect(wrapped.decision).toBe("defer");
  const nested = wrapped.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "bun",
  );
  expect(nested).toBeDefined();
  expect(policy.evaluate(nested!).kind).toBe("allow");
});

policyTest.test("defers unreviewed spellings modeled from source", ({ evaluate }) => {
  for (const source of [
    "bun test",
    "bun test tests/example.test.ts",
    "bun typescheck",
    "bun run lint",
    "bun run ./scripts/build-native-node-packages.ts",
    "bun run test tests/example.test.ts",
  ])
    expect(evaluate(source, { initialEnvironment: environment }).decision, source).toBe("defer");
});

policyTest.property(
  "property: only the exact explicit reviewed script spelling can permit",
  { cases: 512, seed: 1 },
  ({ policy, random }) => {
    const words = [
      "run",
      "test",
      "typescheck",
      "build:native-packages",
      "lint",
      "--silent",
      "--",
      "build",
      "native-packages",
      "./scripts/build.ts",
    ];
    const argv = Array.from({ length: random.integer(0, 4) }, () => random.pick(words));
    const expected =
      argv.length === 2 && argv[0] === "run" && (reviewedScripts as readonly string[]).includes(argv[1]!)
        ? "allow"
        : "defer";
    expect(decision(policy, "bun", "external-path", argv), argv.join(" ")).toBe(expected);
  },
);
