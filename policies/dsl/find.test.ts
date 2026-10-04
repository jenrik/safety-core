import { expect } from "bun:test";

import type { InvocationView } from "../../src/policy/types.ts";
import { policyTestForFile } from "../../src/policy/testing.ts";
import type { ValidatedBashPolicy } from "../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);

const DEFERRED = [
  "-exec",
  "-execdir",
  "-ok",
  "-okdir",
  "-delete",
  "-fprint",
  "-fprint0",
  "-fprintf",
  "-fls",
] as const;

const SAFE_WORDS = [
  ".",
  "./src",
  "--",
  "-maxdepth",
  "2",
  "-mindepth",
  "0",
  "-name",
  "*.ts",
  "-type",
  "f",
  "-path",
  "-size",
  "+1M",
  "-perm",
  "-readable",
  "-writable",
  "-executable",
  "-fstype",
  "ext4",
  "-print",
  "-print0",
  "-printf",
  "%p\\n",
  "-ls",
  "-prune",
  "-quit",
  "-depth",
  "-xdev",
  "-regextype",
  "posix-extended",
  "-newer",
  "a",
  "-files0-from",
  "list.txt",
] as const;

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

policyTest.test("permits read-only find spellings in any operand form", ({ policy }) => {
  for (const [executable, argv] of [
    ["find", []],
    ["find", ["."]],
    ["find", [".", "-name", "*.ts"]],
    ["find", ["-maxdepth", "2", ".", "-print"]],
    ["find", [".", "-type", "f", "-print0"]],
    ["find", ["-name", "x", "-print", "."]],
    ["find", [".", "-newer", "a", "-size", "+1M"]],
    ["find", [".", "-executable", "-print"]],
    ["find", [".", "-fstype", "ext4", "-false"]],
    ["find", [".", "--", "-name"]],
    ["find", [".", "-files0-from", "list.txt"]],
    ["find", [".", "-files0-from", "-"]],
    ["/usr/bin/find", [".", "-print"]],
    ["/nix/store/abc-findutils-4.11.0/bin/find", [".", "-type", "d"]],
  ] as const)
    expect(decision(policy, executable, "external-path", argv), `${executable} ${argv.join(" ")}`).toBe("allow");
});

policyTest.test("defers every action that executes, deletes, or writes a file", ({ policy }) => {
  for (const token of DEFERRED)
    for (const argv of [
      [token],
      [".", token],
      [".", "-name", "x", token],
      ["-maxdepth", "1", ".", token, "-print"],
      [token, ".", "-print"],
    ] as const)
      expect(decision(policy, "find", "external-path", argv), `${argv.join(" ")}`).toBe("defer");
});

policyTest.test("defers execution actions with either terminator", ({ policy }) => {
  for (const argv of [
    [".", "-exec", "rm", "{}", ";"],
    [".", "-exec", "rm", "{}", "+"],
    [".", "-execdir", "rm", "{}", ";"],
    [".", "-execdir", "rm", "{}", "+"],
    [".", "-ok", "rm", "{}", ";"],
    [".", "-okdir", "rm", "{}", ";"],
    ["-name", "*.tmp", "-exec", "true", ";"],
    [".", "-exec", "sh", "-c", "anything"],
  ] as const)
    expect(decision(policy, "find", "external-path", argv), argv.join(" ")).toBe("defer");
});

policyTest.test("defers destructive and file-writing actions", ({ policy }) => {
  for (const argv of [
    [".", "-delete"],
    [".", "-name", "*.tmp", "-delete"],
    [".", "-fprint", "out.txt"],
    [".", "-fprint0", "out.bin"],
    [".", "-fprintf", "out.txt", "%p\\n"],
    [".", "-fls", "out.ls"],
  ] as const)
    expect(decision(policy, "find", "external-path", argv), argv.join(" ")).toBe("defer");
});

policyTest.test("fail-closed on action tokens used as another primary's value", ({ policy }) => {
  // Documented false positive: the value position is intentionally not parsed.
  for (const argv of [
    [".", "-name", "-delete"],
    [".", "-name", "-exec"],
    [".", "-path", "-fprintf", "-print"],
  ] as const)
    expect(decision(policy, "find", "external-path", argv), argv.join(" ")).toBe("defer");
});

policyTest.test("does not confuse the -executable test with the -exec action", ({ policy }) => {
  for (const argv of [
    [".", "-executable"],
    [".", "-executable", "-print"],
    [".", "-not", "-executable", "-print"],
  ] as const)
    expect(decision(policy, "find", "external-path", argv), argv.join(" ")).toBe("allow");
});

policyTest.test("defers non-external targets and ignores other basenames", ({ policy }) => {
  for (const target of ["builtin", "unresolved"] as const)
    expect(decision(policy, "find", target, [".", "-print"]), target).toBe("defer");
  for (const executable of ["findutils", "finds", "gfind", "fd", "/usr/bin/gfind", "find.exe"])
    expect(decision(policy, executable, "external-path", [".", "-print"]), executable).toBe("ignore");
});

policyTest.test("denies shell-function shadowing and permits command to bypass it", ({ policy, evaluate }) => {
  expect(decision(policy, "find", "shell-function", [".", "-print"])).toBe("deny");

  const local = evaluate("find() { :; }; find . -print");
  expect(local.decision).toBe("deny");
  expect(local.events).toContainEqual(
    expect.objectContaining({
      kind: "invocation",
      executable: { kind: "known", value: "find" },
      executionTarget: "shell-function",
    }),
  );

  const imported = evaluate("find . -print", {
    initialEnvironment: { kind: "verified", values: { "BASH_FUNC_find%%": "() { :; }" } },
  });
  expect(imported.decision).toBe("deny");

  const bypassed = evaluate("find() { :; }; command find . -print");
  const externalFind = bypassed.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === "find" &&
      event.executionTarget === "external-path",
  );
  expect(externalFind).toBeDefined();
  expect(policy.evaluate(externalFind!).kind).toBe("allow");
});

policyTest.property("read-only find permutations always allow", { cases: 256, seed: 1 }, ({ policy, random, index }) => {
  const length = random.integer(0, 10);
  const argv = Array.from({ length }, () => random.pick(SAFE_WORDS));
  expect(
    decision(policy, index % 2 === 0 ? "find" : "/nix/store/abc-findutils-4.11.0/bin/find", "external-path", argv),
    `case ${index}: ${argv.join(" ")}`,
  ).toBe("allow");
});

policyTest.property("a deferred action anywhere always defers", { cases: 256, seed: 7 }, ({ policy, random }) => {
  const length = random.integer(0, 8);
  const argv = Array.from({ length }, () => random.pick(SAFE_WORDS));
  argv.splice(random.integer(0, argv.length), 0, random.pick(DEFERRED));
  expect(decision(policy, "find", "external-path", argv), argv.join(" ")).toBe("defer");
});
