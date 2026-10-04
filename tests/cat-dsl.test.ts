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

const catPath = new URL("../policies/dsl/cat.policy.json", import.meta.url);
const catPolicy = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(readFileSync(catPath, "utf8"))),
  catPath.pathname,
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
  return catPolicy.evaluate({
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
    policies: [catPolicy],
  });
}

describe("cat DSL policy", () => {
  test("permits external cat basename spellings with every operand form", () => {
    for (const [executable, argv] of [
      ["cat", []],
      ["cat", ["README.md"]],
      ["cat", ["--", "-literal-name", "credentials.json"]],
      ["cat", ["-AbenstuvET", ".env", "id_ed25519"]],
      ["/usr/bin/cat", ["/etc/shadow"]],
    ] as const)
      expect(decision(executable, "external-path", argv), `${executable} ${argv.join(" ")}`).toBe("allow");
  });

  test("defers non-external selected targets and ignores other basenames", () => {
    for (const target of ["builtin", "unresolved"] as const) expect(decision("cat", target)).toBe("defer");
    for (const executable of ["bat", "catalog", "cat.exe", "/usr/bin/gcat"])
      expect(decision(executable, "external-path"), executable).toBe("ignore");
  });

  test("denies shell-function shadowing and permits command to bypass it", () => {
    expect(decision("cat", "shell-function", ["README.md"])).toBe("deny");

    const local = analyze("cat() { :; }; cat README.md");
    expect(local.decision).toBe("deny");
    expect(local.events).toContainEqual(
      expect.objectContaining({
        kind: "invocation",
        executable: { kind: "known", value: "cat" },
        executionTarget: "shell-function",
      }),
    );

    const imported = analyze("cat README.md", { "BASH_FUNC_cat%%": "() { :; }" });
    expect(imported.decision).toBe("deny");

    const bypassed = analyze("cat() { :; }; command cat README.md");
    const externalCat = bypassed.events.find(
      (event): event is InvocationView =>
        event.kind === "invocation" &&
        event.executable?.kind === "known" &&
        event.executable.value === "cat" &&
        event.executionTarget === "external-path",
    );
    expect(externalCat).toBeDefined();
    expect(catPolicy.evaluate(externalCat!).kind).toBe("allow");
  });

  test("property: arbitrary argument sequences do not change an external cat decision", () => {
    const words = ["", "--", "-A", "README.md", ".env", "credentials.json", "$(unknown)"];
    let state = 0x6d2b79f5;
    for (let seed = 0; seed < 256; seed++) {
      const argv = Array.from({ length: state % 8 }, () => {
        state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
        return words[state % words.length]!;
      });
      expect(
        decision(seed % 2 === 0 ? "cat" : "/nix/store/coreutils/bin/cat", "external-path", argv),
        `seed ${seed}`,
      ).toBe("allow");
    }
  });
});
