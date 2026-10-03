import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";

const path = new URL("../policies/dsl/jfrog/jf-rt-ping-read-only.policy.json", import.meta.url);
const policy = createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(path, "utf8"))), path.pathname);

function decision(args: readonly string[], overrides: Record<string, unknown> = {}): string {
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

describe("jf rt ping read-only DSL policy", () => {
  test("permits the documented ping command and p alias", () => {
    for (const args of [
      ["rt", "ping"],
      ["rt", "p"],
      ["rt", "ping", "--format", "json"],
      ["rt", "p", "--format=table"],
    ]) {
      expect(decision(args), args.join(" ")).toBe("allow");
    }
  });

  test("property: aliases, documented output values, and option forms compose", () => {
    const commands = ["ping", "p"];
    const values = ["json", "table"];
    for (const command of commands)
      for (const value of values) {
        for (const option of [["--format", value], [`--format=${value}`]]) {
          expect(decision(["rt", command, ...option]), `rt ${command} ${option.join(" ")}`).toBe("allow");
        }
        for (const repeated of values) {
          expect(
            decision(["rt", command, "--format", value, `--format=${repeated}`]),
            `rt ${command} ${value}/${repeated}`,
          ).toBe("allow");
        }
      }
  });

  test("defers non-ping paths, unreviewed flags, malformed formats, and extra input", () => {
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
      expect(decision(args), args.join(" ")).toBe("defer");

    const unknown = { kind: "unknown", reason: { kind: "expansion" } };
    expect(
      decision([], {
        argv: [
          { kind: "known", value: "rt" },
          { kind: "known", value: "ping" },
          { kind: "known", value: "--format" },
          unknown,
        ],
      }),
    ).toBe("defer");
  });

  test("defers modeled unsafe execution routes and environment configuration", () => {
    expect(
      decision(["rt", "ping"], { redirects: [{ kind: "input", target: { kind: "known", value: "payload" } }] }),
    ).toBe("defer");
    expect(
      decision(["rt", "ping"], { assignments: { JFROG_CLI_SERVER_ID: { kind: "known", value: "synthetic" } } }),
    ).toBe("defer");
    expect(
      decision(["rt", "ping"], {
        environment: { __SAFETY_CORE_BASH_FUNCTION_jf: { kind: "known", value: "present" } },
      }),
    ).toBe("defer");
    expect(
      decision(["rt", "ping"], {
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
      expect(decision(["rt", "ping"], { environment: { [name]: { kind: "known", value: "synthetic" } } }), name).toBe(
        "defer",
      );
      expect(decision(["rt", "ping"], { environment: { [name]: { kind: "known", value: "" } } }), `${name}=empty`).toBe(
        "allow",
      );
    }
    expect(decision(["rt", "ping"], { missingBindings: "unknown" })).toBe("defer");
  });
});
