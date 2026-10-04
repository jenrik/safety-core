import { expect } from "bun:test";

import type { InvocationView } from "../../src/policy/types.ts";
import { policyTestForFile } from "../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

function decision(
  policy: ValidatedBashPolicy,
  executable: string,
  executionTarget: InvocationView["executionTarget"],
  argv: readonly string[] = [],
): string {
  const basename = executable.split("/").filter(Boolean).at(-1) ?? "";
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

policyTest.test("permits external cat basename spellings with every operand form", ({ policy }) => {
  for (const [executable, argv] of [
    ["cat", []],
    ["cat", ["README.md"]],
    ["cat", ["--", "-literal-name", "credentials.json"]],
    ["cat", ["-AbenstuvET", ".env", "id_ed25519"]],
    ["/usr/bin/cat", ["/etc/shadow"]],
  ] as const)
    expect(decision(policy, executable, "external-path", argv), `${executable} ${argv.join(" ")}`).toBe("allow");
});

policyTest.test("defers non-external selected targets and ignores other basenames", ({ policy }) => {
  for (const target of ["builtin", "unresolved"] as const) expect(decision(policy, "cat", target)).toBe("defer");
  for (const executable of ["bat", "catalog", "cat.exe", "/usr/bin/gcat"])
    expect(decision(policy, executable, "external-path"), executable).toBe("ignore");
});

policyTest.test("denies shell-function shadowing and permits command to bypass it", ({ policy, evaluate }) => {
  expect(decision(policy, "cat", "shell-function", ["README.md"])).toBe("deny");

  const local = evaluate("cat() { :; }; cat README.md");
  expect(local.decision).toBe("deny");
  expect(local.events).toContainEqual(
    expect.objectContaining({
      kind: "invocation",
      executable: { kind: "known", value: "cat" },
      executionTarget: "shell-function",
    }),
  );

  const imported = evaluate("cat README.md", { initialEnvironment: { kind: "verified", values: { "BASH_FUNC_cat%%": "() { :; }" } } });
  expect(imported.decision).toBe("deny");

  const bypassed = evaluate("cat() { :; }; command cat README.md");
  const externalCat = bypassed.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === "cat" &&
      event.executionTarget === "external-path",
  );
  expect(externalCat).toBeDefined();
  expect(policy.evaluate(externalCat!).kind).toBe("allow");
});

policyTest.property("arbitrary argument sequences do not change an external cat decision", { cases: 256, seed: 1 }, ({ policy, random, index }) => {
  const words = ["", "--", "-A", "README.md", ".env", "credentials.json", "$(unknown)"];
  const argv = Array.from({ length: random.integer(0, 7) }, () => random.pick(words));
  expect(decision(policy, index % 2 === 0 ? "cat" : "/nix/store/coreutils/bin/cat", "external-path", argv), `case ${index}`).toBe("allow");
});
