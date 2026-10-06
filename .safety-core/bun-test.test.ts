import { expect } from "bun:test";
import { fileURLToPath } from "node:url";

import { completePolicyInitialEnvironment } from "../src/index.ts";
import { createPolicyTestSuite } from "../src/policy/testing.ts";
import type { InvocationView, ValidatedBashPolicy } from "../src/policy/types.ts";

const policyPath = fileURLToPath(new URL("./bun-test.policy.json", import.meta.url));
const policyTest = createPolicyTestSuite(policyPath, fileURLToPath(import.meta.url));

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
  argv: readonly string[],
  executable = "bun",
  executionTarget: InvocationView["executionTarget"] = "external-path",
): string {
  return policy.evaluate(invocation(executable, executionTarget, argv)).kind;
}

function argvOf(event: InvocationView): string[] {
  return event.argv.map((word) => (word.kind === "known" ? word.value : "<unknown>"));
}

policyTest.test("permits the test runner with project-relative test selection", ({ policy }) => {
  for (const argv of [
    ["test"],
    ["test", "tests/example.test.ts"],
    ["test", "tests/one.test.ts", "packages/core/two.test.ts"],
    ["test", "bash-options"],
    ["test", "./tests/*.test.ts"],
    ["test", "."],
  ])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("allow");
});

policyTest.test("permits the reviewed flag inventory before, after, and between patterns", ({ policy }) => {
  const flags = [
    ["-t", "allows the intended command"],
    ["-tallows the intended command"],
    ["-t=ok"],
    ["--test-name-pattern", "ok"],
    ["--test-name-pattern=ok"],
    ["--timeout", "20000"],
    ["--timeout=20000"],
    ["--retry", "2"],
    ["--retry=2"],
    ["--rerun-each", "2"],
    ["--rerun-each=2"],
    ["--max-concurrency", "1"],
    ["--max-concurrency=1"],
    ["--parallel-delay", "1"],
    ["--parallel-delay=1"],
    ["--seed", "1"],
    ["--seed=1"],
    ["--shard", "1/1"],
    ["--shard=1/1"],
    ["--path-ignore-patterns", "zzz"],
    ["--path-ignore-patterns=zzz"],
    ["--coverage-reporter", "text"],
    ["--coverage-reporter=text"],
    ["--bail"],
    ["--bail=2"],
    ["--changed"],
    ["--changed=HEAD"],
    ["--parallel"],
    ["--parallel=2"],
    ["--coverage"],
    ["--no-coverage"],
    ["--only"],
    ["--todo"],
    ["--pass-with-no-tests"],
    ["--concurrent"],
    ["--randomize"],
    ["--isolate"],
    ["--dots"],
    ["--only-failures"],
  ];
  for (const flag of flags) {
    const label = flag.join(" ");
    expect(decision(policy, ["test", ...flag]), `bun test ${label}`).toBe("allow");
    expect(decision(policy, ["test", ...flag, "tests/example.test.ts"]), `bun test ${label} <path>`).toBe("allow");
    expect(decision(policy, ["test", "tests/example.test.ts", ...flag]), `bun test <path> ${label}`).toBe("allow");
  }
  expect(decision(policy, ["test", "-t", "ok", "--bail", "tests/a.test.ts", "--coverage"])).toBe("allow");
});

policyTest.test("defers project-escaping test selection", ({ policy }) => {
  for (const argv of [
    ["test", "/tmp/evil.test.ts"],
    ["test", "/etc/passwd"],
    ["test", "../evil.test.ts"],
    ["test", ".."],
    ["test", "a/../b.test.ts"],
    ["test", "a/.."],
    ["test", "../"],
    ["test", "~/evil.test.ts"],
    ["test", "--", "../evil.test.ts"],
    ["test", "tests/ok.test.ts", "/tmp/evil.test.ts"],
    ["test", "--", "--timeout", "/tmp/evil.test.ts"],
    ["test", "--", "--coverage-reporter", "/tmp/evil.test.ts"],
    ["test", "--", "-t", "/tmp/evil.test.ts"],
    ["test", "--", "-t", "../evil.test.ts"],
    ["test", "--", "--", "tests/ok.test.ts"],
    ["test", "--", "--bail", "/tmp/evil.test.ts"],
  ])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("defer");
});

policyTest.test("permits every required-value flag whose separate value looks like an escaping path", ({ policy }) => {
  // Bun 1.3.13 consumes the separate token as the flag's value, so an
  // escaping-looking word in that position is never a positional test path.
  // The policy's unconditional separate-value consumption matches Bun.
  for (const flag of [
    "-t",
    "--test-name-pattern",
    "--timeout",
    "--retry",
    "--rerun-each",
    "--max-concurrency",
    "--parallel-delay",
    "--seed",
    "--shard",
    "--path-ignore-patterns",
    "--coverage-reporter",
  ])
    expect(decision(policy, ["test", flag, "/tmp/evil.test.ts"]), `bun test ${flag} /tmp/evil.test.ts`).toBe("allow");
});

policyTest.test("permits `-t` attached values without treating them as clustered short flags", ({ policy }) => {
  // Bun 1.3.13 parses `-tu` as the pattern `u` (attached value), not as
  // `-t -u`, and `-t -u` / `-t-u` supply `-u` as the pattern. The policy's
  // `attachedShort` form matches, and none of these spellings contains the
  // standalone `--` word.
  for (const argv of [["test", "-tu"], ["test", "-t", "-u"], ["test", "-t-u"]])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("allow");
});

policyTest.test("defers any invocation containing the standalone `--` word", ({ policy }) => {
  // `--` is never modeled as a terminator or as an option value. An `argv`
  // fold detects the exact word anywhere in the invocation, so both the
  // command-line terminator and a `--` that Bun would consume as an option's
  // value defer rather than authorizing a differently-parsed command.
  for (const argv of [
    ["test", "--"],
    ["test", "--", "tests/example.test.ts"],
    ["test", "--", "--"],
    ["test", "--", "--timeout", "/tmp/evil.test.ts"],
    ["test", "--", "--coverage"],
    ["test", "--", "-t", "/tmp/evil.test.ts"],
    ["test", "-t", "--", "--seed", "/tmp/evil.test.ts"],
    ["test", "-t", "--", "--timeout", "/tmp/evil.test.ts"],
    ["test", "--timeout", "--", "tests/inside.test.ts"],
    ["test", "--seed", "--", "/tmp/evil.test.ts"],
    ["test", "tests/example.test.ts", "--"],
    ["test", "tests/example.test.ts", "--", "packages/core"],
    ["test", "-t", "--"],
  ])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("defer");
});

policyTest.test("defers flags that appear before the test subcommand", ({ policy }) => {
  for (const argv of [
    ["--coverage", "test"],
    ["--timeout", "5", "test"],
    ["--bail", "test"],
    ["--seed=1", "test"],
    ["-t", "ok", "test"],
  ])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("defer");
});

policyTest.test("defers excluded flags, other subcommands, and non-external targets", ({ policy }) => {
  for (const argv of [
    [],
    ["run", "test"],
    ["install"],
    ["--preload=./setup.ts"],
    ["--require=./setup.ts"],
    ["--import=./setup.ts"],
    ["-u"],
    ["--update-snapshots"],
    ["--watch"],
    ["--hot"],
    ["--cwd=/tmp"],
    ["--cwd", "/tmp", "test"],
    ["-c", "bunfig.toml"],
    ["--config=bunfig.toml"],
    ["--env-file=.env"],
    ["--no-env-file"],
    ["--coverage-dir=/tmp/coverage"],
    ["--reporter=junit"],
    ["--reporter-outfile=/tmp/junit.xml"],
    ["-e", "console.log(1)"],
    ["--eval=console.log(1)"],
    ["-p", "1"],
    ["--install=force"],
    ["--prefer-latest"],
    ["--smol"],
    ["--inspect"],
    ["--cpu-prof"],
    ["--heap-prof"],
    ["--test-worker"],
    ["--unknown-flag"],
    ["test-extra"],
    ["", "test"],
  ])
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("defer");

  for (const executable of ["bunx", "node", "bun.exe"])
    expect(decision(policy, ["test"], executable), executable).toBe("ignore");
  for (const target of ["builtin", "shell-function", "unresolved"] as const)
    expect(decision(policy, ["test"], "bun", target), target).toBe("defer");
  for (const executable of ["/usr/bin/bun", "./bun"])
    expect(decision(policy, ["test"], executable), executable).toBe("defer");
});

policyTest.test("permits the dev-loop test invocations modeled from source", ({ evaluate }) => {
  for (const source of [
    "bun test",
    "bun test tests/example.test.ts packages/core",
    "bun test -t ok tests/example.test.ts",
    "bun test --bail tests/example.test.ts",
    "bun test --coverage --seed=1",
    "bun test bash-options",
  ]) {
    const result = evaluate(source, { initialEnvironment: environment });
    expect(result.decision, source).toBe("allow");
    const [event] = result.events;
    expect(event).toMatchObject({
      kind: "invocation",
      executable: { kind: "known", value: "bun" },
      executionTarget: "external-path",
    });
    if (event?.kind === "invocation") expect(argvOf(event)[0]).toBe("test");
  }
});

policyTest.test("defers modeling gaps from source", ({ evaluate, policy }) => {
  for (const source of [
    "bun test /tmp/evil.test.ts",
    "bun test ../evil.test.ts",
    "bun test --preload=./setup.ts",
    "bun test --watch",
    "bun test -u",
    "bun run test",
    "FOO=1 bun test",
    "bun() { :; }; bun test",
    "command bun test",
    "bun --coverage test",
    "bun test -- --timeout /tmp/evil.test.ts",
    "bun test -- -t /tmp/evil.test.ts",
    "bun test --",
    "bun test -- tests/example.test.ts",
    "bun test -t -- --seed /tmp/evil.test.ts",
    "bun test --timeout -- tests/example.test.ts",
    "bun test tests/example.test.ts --",
  ])
    expect(evaluate(source, { initialEnvironment: environment }).decision, source).toBe("defer");

  const wrapped = evaluate("command bun test", { initialEnvironment: environment });
  const nested = wrapped.events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "bun",
  );
  expect(nested).toBeDefined();
  expect(policy.evaluate(nested!).kind).toBe("allow");
});

policyTest.test("permits an empty proven-empty pattern word and defers unknown pattern input", ({ policy, evaluate }) => {
  // A verified environment proves the unset variable empty, and bun treats an empty pattern as "all tests".
  expect(evaluate('bun test "$UNSET_PATTERN"', { initialEnvironment: environment }).decision).toBe("allow");

  // The same spelling under an environment that cannot prove the value stays deferred.
  expect(
    evaluate('bun test "$UNKNOWN_PATTERN"', {
      initialEnvironment: { kind: "filtered", values: { PATH: "/usr/bin:/bin" }, unset: [] },
    }).decision,
  ).toBe("defer");

  const unknownWord = {
    kind: "unknown" as const,
    reason: { kind: "unknown-variable" as const, span: { start: 0, end: 0 } },
  };
  expect(
    policy.evaluate({
      ...invocation("bun", "external-path", []),
      argv: [{ kind: "known" as const, value: "test" }, unknownWord],
    }).kind,
  ).toBe("defer");
});

policyTest.test("defers an unknown word consumed as a required option value", ({ policy, evaluate }) => {
  // The allow proof requires every argv word to be known and non-`--`. An
  // unknown word in a required-value position must defer: at execution time an
  // expansion can produce a standalone `--` (and, unquoted, extra positional
  // words such as an outside test path).
  const unknownWord = {
    kind: "unknown" as const,
    reason: { kind: "unknown-variable" as const, span: { start: 0, end: 0 } },
  };
  const valueFlags = [
    "-t",
    "--test-name-pattern",
    "--timeout",
    "--retry",
    "--rerun-each",
    "--max-concurrency",
    "--parallel-delay",
    "--seed",
    "--shard",
    "--path-ignore-patterns",
    "--coverage-reporter",
  ];
  for (const flag of valueFlags) {
    const argv = [
      { kind: "known" as const, value: "test" },
      { kind: "known" as const, value: flag },
      unknownWord,
    ];
    expect(policy.evaluate({ ...invocation("bun", "external-path", []), argv }).kind, `bun test ${flag} <unknown>`).toBe(
      "defer",
    );
    expect(
      policy.evaluate({
        ...invocation("bun", "external-path", []),
        argv: [...argv, { kind: "known" as const, value: "tests/a.test.ts" }],
      }).kind,
      `bun test ${flag} <unknown> tests/a.test.ts`,
    ).toBe("defer");
  }

  // Source-level: a filtered environment leaves the value unknown, and the
  // analyzer models `"$@"`, command substitution, and indirect expansion as
  // unknown words too.
  const filtered = { kind: "filtered" as const, values: { PATH: "/usr/bin:/bin" }, unset: [] };
  for (const source of [
    'bun test -t "$UNKNOWN_PATTERN"',
    'bun test --timeout "$UNKNOWN"',
    'bun test -t "$@"',
    'bun test --timeout "$@"',
    'bun test -t $(echo ok)',
    'bun test -t "${!N}"',
  ])
    expect(evaluate(source, { initialEnvironment: filtered }).decision, source).toBe("defer");
});

policyTest.property(
  "property: an unknown argv word never permits a test invocation",
  { cases: 384, seed: 17 },
  ({ policy, random }) => {
    const unknownWord = {
      kind: "unknown" as const,
      reason: { kind: "unknown-variable" as const, span: { start: 0, end: 0 } },
    };
    const known = ["-t", "--timeout", "--coverage", "ok", "tests/a.test.ts", "/tmp/evil.test.ts", "--"];
    const items: (InvocationView["argv"][number])[] = Array.from({ length: random.integer(0, 3) }, () => ({
      kind: "known" as const,
      value: random.pick(known),
    }));
    // Exactly one unknown word, at a random position, so the property always
    // exercises a genuinely unproven argv item.
    items.splice(random.integer(0, items.length), 0, unknownWord);
    const argv = [{ kind: "known" as const, value: "test" }, ...items];
    expect(policy.evaluate({ ...invocation("bun", "external-path", []), argv }).kind, JSON.stringify(argv)).not.toBe(
      "allow",
    );
  },
);

policyTest.property(
  "property: a standalone `--` anywhere in argv never permits a test invocation",
  { cases: 512, seed: 13 },
  ({ policy, random }) => {
    const flagged = ["--timeout", "--coverage-reporter", "-t", "--bail", "--preload=x", "-u"];
    const escaping = ["/tmp/evil.test.ts", "../evil.test.ts", "..", "a/../b", "~/evil"];
    const relative = ["tests/a.test.ts", "packages/core", "ok"];
    const before = Array.from({ length: random.integer(0, 4) }, () =>
      random.pick([...flagged, ...escaping, ...relative]),
    );
    const after = Array.from({ length: random.integer(0, 4) }, () =>
      random.pick([...flagged, ...escaping, ...relative]),
    );
    const argv = ["test", ...before, "--", ...after];
    expect(decision(policy, argv), `bun ${argv.join(" ")}`).toBe("defer");
  },
);

policyTest.property(
  "property: project-escaping words never permit a test invocation",
  { cases: 512, seed: 7 },
  ({ policy, random }) => {
    const escaping = ["/tmp/evil.test.ts", "/etc/passwd", "../evil.test.ts", "..", "a/../b", "a/..", "../", "~/evil"];
    const neutral = ["tests/a.test.ts", "packages/core", "ok", "./tests/*.test.ts", "--bail", "--coverage", "--"];
    const argv = [
      "test",
      ...Array.from({ length: random.integer(1, 5) }, () =>
        random.boolean() ? random.pick(escaping) : random.pick(neutral),
      ),
      random.pick(escaping),
    ];
    expect(decision(policy, argv), argv.join(" ")).not.toBe("allow");
  },
);

policyTest.property(
  "property: relative patterns and reviewed flags permit in any order",
  { cases: 256, seed: 11 },
  ({ policy, random }) => {
    const blocks = [
      ["tests/a.test.ts"],
      ["packages/core", "ok"],
      ["-t", "ok"],
      ["--bail"],
      ["--coverage"],
      ["--seed=1"],
      ["--test-name-pattern", "spec"],
    ];
    const argv = ["test", ...random.shuffle(blocks).flat()];
    expect(decision(policy, argv), argv.join(" ")).toBe("allow");
  },
);

policyTest.test("defers a terminator even after reviewed flags", ({ policy }) => {
  expect(decision(policy, ["test", "--coverage", "--", "tests/a.test.ts"])).toBe("defer");
  expect(decision(policy, ["test", "--", "--coverage", "tests/a.test.ts"])).toBe("defer");
  expect(decision(policy, ["test", "--coverage", "tests/a.test.ts"])).toBe("allow");
});
