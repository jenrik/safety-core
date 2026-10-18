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

policyTest.test("permits GNU tail operands and arbitrary shell redirections", ({ policy, evaluate }) => {
  for (const [executable, argv] of [
    ["tail", []],
    ["tail", ["-n", "+10", "README.md"]],
    ["tail", ["-c-1", "--", "-literal-name"]],
    ["/nix/store/coreutils/bin/tail", ["-qv", "--pid=123", "/any/file"]],
  ] as const)
    expect(decision(policy, executable, "external-path", argv), `${executable} ${argv.join(" ")}`).toBe("allow");

  for (const source of [
    "tail < input > output",
    "tail -n 1 file 2>> errors",
    "tail <<< payload",
    "tail 3<input 4>output",
  ]) {
    const invocation = externalInvocation(evaluate(source), "tail");
    expect(invocation.redirects.length, source).toBeGreaterThan(0);
    expect(policy.evaluate(invocation).kind, source).toBe("allow");
  }
});

policyTest.test("denies a shadowing function and defers other targets", ({ policy, evaluate }) => {
  expect(decision(policy, "tail", "shell-function", ["README.md"])).toBe("deny");
  for (const target of ["builtin", "unresolved"] as const) expect(decision(policy, "tail", target)).toBe("defer");
  for (const executable of ["gtail", "tailor", "tail.exe"])
    expect(decision(policy, executable, "external-path")).toBe("ignore");
  expect(evaluate("tail() { :; }; tail README.md").decision).toBe("deny");
  expect(policy.evaluate(externalInvocation(evaluate("tail() { :; }; command tail README.md"), "tail")).kind).toBe(
    "allow",
  );
});

policyTest.property(
  "arbitrary GNU tail argument sequences remain allowed",
  { cases: 256, seed: 1 },
  ({ policy, random, index }) => {
    const words = ["", "--", "-n", "+10", "--bytes=-1", "--follow=name", "README.md", "/any/file", "$(unknown)"];
    const argv = Array.from({ length: random.integer(0, 8) }, () => random.pick(words));
    expect(
      decision(policy, index % 2 === 0 ? "tail" : "/nix/store/coreutils/bin/tail", "external-path", argv),
      `case ${index}`,
    ).toBe("allow");
  },
);

function externalInvocation(result: { readonly events: readonly InvocationView[] }, name: string): InvocationView {
  const invocation = result.events.find(
    (event) =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === name &&
      event.executionTarget === "external-path",
  );
  if (!invocation) throw new Error(`missing external ${name} invocation`);
  return invocation;
}
