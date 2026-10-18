import { expect } from "bun:test";

import type { InvocationView, ValidatedBashPolicy } from "../../src/policy/types.ts";
import { policyTestForFile } from "../../src/policy/testing.ts";

const policyTest = policyTestForFile(import.meta.url);

const EVIDENCE_DIGEST = "cb11f85f1fc52c605e6b458568d16206ce06bb3f9e2beccd83a355445a8000e9";

function decision(
  policy: ValidatedBashPolicy,
  argv: readonly string[],
  assignments: readonly string[] = [],
  target: InvocationView["executionTarget"] = "external-path",
  executable = "sed",
): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: executable },
    executionTarget: target,
    executableIdentity: {
      qualification: "incomplete",
      spelling: executable,
      basename: executable.split("/").at(-1)!,
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: argv.map((value) => ({ kind: "known" as const, value })),
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: Object.fromEntries(assignments.map((name) => [name, { kind: "known" as const, value: "C" }])),
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  }).kind;
}

function unknownOperandDecision(policy: ValidatedBashPolicy, index: 1 | 2): string {
  const argv = [
    { kind: "known" as const, value: "-n" },
    { kind: "known" as const, value: "1p" },
    { kind: "known" as const, value: "file" },
  ];
  argv[index] = { kind: "unknown", reason: { kind: "test" } } as never;
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "sed" },
    executionTarget: "external-path",
    executableIdentity: {
      qualification: "incomplete",
      spelling: "sed",
      basename: "sed",
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
  }).kind;
}

policyTest.test("permits each declared quiet spelling and numeric print program", ({ policy }) => {
  for (const argv of [
    ["-n", "1,80p", "policies/dsl/tea/open.policy.json", "README.md"],
    ["--quiet", "-s", "80p", "README.md"],
    ["--separate", "--silent", "1,2p", "--", "-literal"],
  ] as const)
    expect(decision(policy, argv), argv.join(" ")).toBe("allow");
});

policyTest.test(
  "reproduces validation and explain evidence through core APIs",
  ({ policy, policyPath, policySet, evaluate }) => {
    expect(policySet.sources).toEqual([{ canonicalPath: policyPath, scope: "global", sha256: EVIDENCE_DIGEST }]);
    for (const [source, expected] of [
      ["sed -n -s 1,80p policies/dsl/tea/open.policy.json README.md", "allow"],
      ["POSIXLY_CORRECT=1 sed --separate --silent 1p -- -literal", "allow"],
      ["sed -n 1p README.md -e d", "defer"],
    ] as const) {
      const result = evaluate(source);
      const sed = result.events.find(
        (event): event is InvocationView =>
          event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "sed",
      );
      expect(sed, source).toBeDefined();
      expect(policy.evaluate(sed!).kind, source).toBe(expected);
      expect(result.decision, source).toBe(expected);
    }
  },
);

policyTest.test("defers every excluded grammar and target", ({ policy }) => {
  for (const argv of [
    ["1,80p", "file"],
    ["-n", "1,80p"],
    ["-n", "1,80p", ""],
    ["-n", "1,80p", "-"],
    ["-n", "1,80p", "--", "-"],
    ["-n", "1,80p", "-option"],
    ["-n", "1,80p", "--"],
    ["-n", "0,80p", "file"],
    ["-n", "01,80p", "file"],
    ["-n", "1,80P", "file"],
    ["-n", "1 p", "file"],
    ["-n", "$p", "file"],
    ["-n", "/pattern/p", "file"],
    ["-n", "1,80p;d", "file"],
    ["-nn", "1p", "file"],
    ["-ns", "1p", "file"],
    ["--quiet=1", "1p", "file"],
    ["-n", "-n", "1p", "file"],
    ["-s", "-s", "-n", "1p", "file"],
    ["-n", "1p", "-s", "file"],
  ] as const)
    expect(decision(policy, argv), argv.join(" ")).toBe("defer");
  expect(decision(policy, ["-n", "1p", "file"], [], "shell-function")).toBe("defer");
  expect(decision(policy, ["-n", "1p", "file"], [], "builtin")).toBe("defer");
  expect(decision(policy, ["-n", "1p", "file"], [], "unresolved")).toBe("defer");
  expect(decision(policy, ["-n", "1p", "file"], [], "external-path", "/usr/bin/sed")).toBe("defer");
  expect(decision(policy, ["-n", "1p", "file"], [], "external-path", "SED")).toBe("ignore");
  expect(unknownOperandDecision(policy, 1)).toBe("defer");
  expect(unknownOperandDecision(policy, 2)).toBe("defer");
});

policyTest.test("permits only locale prefix assignments", ({ policy }) => {
  expect(decision(policy, ["-n", "1p", "file"], ["LC_ALL", "LC_CTYPE", "POSIXLY_CORRECT"])).toBe("allow");
  for (const name of ["LANG", "SED_PROGRAM"])
    expect(decision(policy, ["-n", "1p", "file"], [name]), name).toBe("defer");
});

policyTest.test("permits the sed child with modeled shell redirects", ({ policy, evaluate }) => {
  const result = evaluate("sed -n 1p input < alternate-input > output 2>&1");
  const sed = result.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "sed",
  );
  expect(sed).toBeDefined();
  expect(policy.evaluate(sed!).kind).toBe("allow");
  expect(sed!.ownRedirects).toHaveLength(3);
  expect(result.fileAccesses).toContainEqual(
    expect.objectContaining({ path: expect.stringMatching(/alternate-input$/), operation: "read" }),
  );
  expect(result.fileAccesses).toContainEqual(
    expect.objectContaining({ path: expect.stringMatching(/output$/), operation: "write" }),
  );
  expect(result.decision).toBe("defer");
});

policyTest.test("models POSIXLY_CORRECT terminator and wrapper children separately", ({ policy, evaluate }) => {
  const posix = evaluate("POSIXLY_CORRECT=1 sed -n 1p -- -literal");
  expect(posix.decision).toBe("allow");

  for (const source of ["printf '%s' \"$(sed -n 1p README.md)\"", "sed -n 1p README.md | wc -l"]) {
    const result = evaluate(source);
    const sed = result.events.find(
      (event): event is InvocationView =>
        event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "sed",
    );
    expect(sed, source).toBeDefined();
    expect(policy.evaluate(sed!).kind, source).toBe("allow");
    expect(
      result.events.some(
        (event) =>
          event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value !== "sed",
      ),
      source,
    ).toBe(true);
    expect(result.decision, source).toBe("defer");
  }
});

policyTest.property(
  "quiet synonyms, separate mode, numeric line ranges, and terminator remain equivalent",
  { cases: 256, seed: 4 },
  ({ policy, random }) => {
    const first = random.integer(1, 100000).toString();
    const second = random.integer(1, 100000).toString();
    const program = random.boolean() ? `${first}p` : `${first},${second}p`;
    const quiet = random.pick(["-n", "--quiet", "--silent"]);
    const separate = random.boolean() ? [random.pick(["-s", "--separate"])] : [];
    const options = random.boolean() ? [quiet, ...separate] : [...separate, quiet];
    const argv = random.boolean()
      ? [...options, program, "file", "another"]
      : [...options, program, "--", "-literal-file"];
    expect(decision(policy, argv), argv.join(" ")).toBe("allow");
  },
);

function isDeclaredGrammar(argv: readonly string[]): boolean {
  const quiet = new Set(["-n", "--quiet", "--silent"]);
  const separate = new Set(["-s", "--separate"]);
  let index = 0;
  let initialSeparate = false;
  if (quiet.has(argv[index] ?? "")) index++;
  else if (separate.has(argv[index] ?? "")) {
    initialSeparate = true;
    index++;
    if (!quiet.has(argv[index] ?? "")) return false;
    index++;
  } else return false;
  if (!initialSeparate && separate.has(argv[index] ?? "")) index++;
  const program = argv[index++];
  if (program === undefined || !/^(?:[1-9]\d*|[1-9]\d*,[1-9]\d*)p$/.test(program)) return false;
  let terminated = false;
  let files = 0;
  for (; index < argv.length; index++) {
    const word = argv[index]!;
    if (!terminated && word === "--") {
      terminated = true;
      continue;
    }
    if (word === "" || word === "-") return false;
    if (!terminated && word.startsWith("-")) return false;
    files++;
  }
  return files > 0;
}

policyTest.property(
  "bounded adversarial argv corpus fails closed outside the declared grammar",
  { cases: 512, seed: 9 },
  ({ policy, random }) => {
    const words = [
      "-n",
      "--quiet",
      "--silent",
      "-s",
      "--separate",
      "1p",
      "1,2p",
      "01p",
      "0p",
      "1P",
      "1p;d",
      "file",
      "another",
      "--",
      "-literal",
      "-e",
      "-",
      "",
    ];
    const argv = Array.from({ length: random.integer(0, 8) }, () => random.pick(words));
    expect(decision(policy, argv), argv.join(" ")).toBe(isDeclaredGrammar(argv) ? "allow" : "defer");
  },
);

policyTest.property(
  "prefix-assignment allowlist remains fail closed",
  { cases: 256, seed: 12 },
  ({ policy, random }) => {
    const allowed = [
      "LC_ADDRESS",
      "LC_ALL",
      "LC_COLLATE",
      "LC_CTYPE",
      "LC_IDENTIFICATION",
      "LC_MEASUREMENT",
      "LC_MESSAGES",
      "LC_MONETARY",
      "LC_NAME",
      "LC_NUMERIC",
      "LC_PAPER",
      "LC_TELEPHONE",
      "LC_TIME",
      "POSIXLY_CORRECT",
    ];
    const candidates = [...allowed, "LANG", "SED_PROGRAM", "PATH", "BASH_ENV"];
    const assignments = Array.from({ length: random.integer(0, 5) }, () => random.pick(candidates));
    expect(decision(policy, ["-n", "1p", "file"], assignments)).toBe(
      assignments.every((name) => allowed.includes(name)) ? "allow" : "defer",
    );
  },
);
