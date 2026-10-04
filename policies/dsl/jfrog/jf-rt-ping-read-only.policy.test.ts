import { expect } from "bun:test";

import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

function decision(policy: ValidatedBashPolicy, args: readonly string[], overrides: Record<string, unknown> = {}): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "jf" },
    executableIdentity: {
      qualification: "incomplete",
      spelling: "jf",
      basename: "jf",
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: args.map((value) => ({ kind: "known" as const, value })),
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

policyTest.test("permits the documented ping command and p alias", ({ policy }) => {
  for (const args of [
    ["rt", "ping"],
    ["rt", "p"],
    ["rt", "ping", "--format", "json"],
    ["rt", "p", "--format=table"],
  ]) {
    expect(decision(policy, args), args.join(" ")).toBe("allow");
  }
});

policyTest.property("aliases, documented output values, and option forms compose", { cases: 100, seed: 17 }, ({ policy, random }) => {
  const command = random.pick(["ping", "p"]);
  const value = random.pick(["json", "table"]);
  const option = random.boolean() ? ["--format", value] : [`--format=${value}`];
  expect(decision(policy, ["rt", command, ...option]), `rt ${command} ${option.join(" ")}`).toBe("allow");
  const repeated = random.pick(["json", "table"]);
  expect(decision(policy, ["rt", command, "--format", value, `--format=${repeated}`])).toBe("allow");
});

policyTest.test("defers non-ping paths, unreviewed flags, malformed formats, and extra input", ({ policy }) => {
  for (const args of [
    [],
    ["rt"],
    ["rt", "repo-create"],
    ["rt", "ping", "--format"],
    ["rt", "ping", "--format", "yaml"],
    ["rt", "p", "--format=JSON"],
    ["rt", "ping", "-f", "json"],
    ["rt", "ping", "--"],
    ["rt", "ping", "extra"],
    ["rt", "--format", "json", "ping"],
    ["rt", "ping", "--url", "https://example.invalid"],
  ])
    expect(decision(policy, args), args.join(" ")).toBe("defer");

  const unknown = { kind: "unknown", reason: { kind: "expansion" } };
  expect(
    decision(policy, [], {
      argv: [
        { kind: "known", value: "rt" },
        { kind: "known", value: "ping" },
        { kind: "known", value: "--format" },
        unknown,
      ],
    }),
  ).toBe("defer");
});

policyTest.test("defers modeled unsafe execution routes and environment configuration", ({ policy }) => {
  expect(
    decision(policy, ["rt", "ping"], { redirects: [{ kind: "input", target: { kind: "known", value: "payload" } }] }),
  ).toBe("defer");
  expect(
    decision(policy, ["rt", "ping"], { assignments: { JFROG_CLI_SERVER_ID: { kind: "known", value: "synthetic" } } }),
  ).toBe("defer");
  expect(
    decision(policy, ["rt", "ping"], { environment: { __SAFETY_CORE_BASH_FUNCTION_jf: { kind: "known", value: "present" } } }),
  ).toBe("defer");
  expect(
    decision(policy, ["rt", "ping"], {
      executable: { kind: "known", value: "/usr/bin/jf" },
      executableIdentity: {
        qualification: "known",
        spelling: "/usr/bin/jf",
        basename: "jf",
        selectedPath: "/usr/bin/jf",
        canonicalTarget: "/usr/bin/jf",
        chain: ["/usr/bin/jf"],
      },
    }),
  ).toBe("defer");

  for (const name of [
    "JFROG_CLI_COMMAND_SUMMARY_OUTPUT_DIR",
    "JFROG_CLI_ENCRYPTION_KEY",
    "JFROG_CLI_HOME_DIR",
    "JFROG_CLI_SERVER_ID",
  ]) {
    expect(decision(policy, ["rt", "ping"], { environment: { [name]: { kind: "known", value: "synthetic" } } }), name).toBe("defer");
    expect(decision(policy, ["rt", "ping"], { environment: { [name]: { kind: "known", value: "" } } }), `${name}=empty`).toBe("allow");
  }
  expect(decision(policy, ["rt", "ping"], { missingBindings: "unknown" })).toBe("defer");
});
