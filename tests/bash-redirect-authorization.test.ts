import { beforeAll, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  analyzeBashWithPolicies,
  checkBashFilePermissions,
  initBundledBashParser,
  parseBashProgram,
  type BashPolicyEvent,
  type HarnessFileAccessRequest,
  type InvocationView,
  type ValidatedBashPolicy,
} from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { validatePolicyDocument } from "../src/policy/dsl/validate.ts";

beforeAll(initBundledBashParser);
const allow: ValidatedBashPolicy = {
  source: { canonicalPath: "/fixture.policy.json" },
  layer: "permission",
  select: [],
  evaluate: () => ({ kind: "allow", reason: [{ kind: "literal", value: "fixture command allowed" }] }),
};
function analyze(
  source: string,
  policies: readonly ValidatedBashPolicy[] = [allow],
  values: Record<string, string> = {},
) {
  return analyzeBashWithPolicies({
    source,
    policies,
    cwd: "/workspace",
    initialEnvironment: { kind: "verified", values },
  });
}
function invocations(events: readonly BashPolicyEvent[]): InvocationView[] {
  return events.filter((event) => event.kind === "invocation");
}
function named(events: readonly BashPolicyEvent[], name: string): InvocationView {
  return invocations(events).find((event) => event.executable?.kind === "known" && event.executable.value === name)!;
}

test("standalone, builtin, function and compound redirects require harness authorization", async () => {
  for (const source of [
    "> out; foo",
    "read X >out; foo",
    ": >out; foo",
    "{ foo; } >out; bar",
    "( foo ) >out; bar",
    "f(){ foo; }; f >out; bar",
    "f(){ foo; } >out; f; bar",
  ]) {
    const result = analyze(source);
    expect(result.commandDecision, source).toBe("allow");
    expect(result.decision, source).toBe("defer");
    expect(result.fileAccesses, source).toHaveLength(1);
    expect(result.fileAccesses![0], source).toMatchObject({
      operation: "write",
      effect: "truncate",
      path: "/workspace/out",
    });
    expect((await checkBashFilePermissions(result, { check: () => "allow" })).decision, source).toBe("allow");
    expect((await checkBashFilePermissions(result, { check: () => "ask" })).decision, source).toBe("defer");
    expect((await checkBashFilePermissions(result, { check: () => "deny" })).decision, source).toBe("deny");
  }
});

test("compound and wrapper descriptors propagate, restore on exit, and open only once", () => {
  for (const source of [
    "{ foo; } >out; bar",
    "( foo ) >out; bar",
    "f(){ foo; }; f >out; bar",
    "f(){ foo; } >out; f; bar",
    "env foo >out; bar",
    "bash -c 'foo' >out; bar",
  ]) {
    const result = analyze(source);
    expect(named(result.events, "foo").io?.["1"], source).toMatchObject({
      kind: "file",
      path: { kind: "known", value: "out" },
    });
    expect(named(result.events, "foo").redirects, source).toHaveLength(1);
    expect(named(result.events, "bar").io?.["1"], source).toEqual({ kind: "inherited", descriptor: 1 });
    expect(named(result.events, "bar").redirects, source).toHaveLength(0);
    expect(result.fileAccesses, source).toHaveLength(1);
  }
});

test("function definition redirects do not execute until the function is called", () => {
  const definition = 'f(){ foo; } >"$(bar)"';
  expect(analyze(definition).events).toHaveLength(0);
  const called = analyze(`${definition}; f; baz`);
  expect(named(called.events, "bar")).toBeDefined();
  expect(named(called.events, "foo").io?.["1"].kind).toBe("file");
  expect(named(called.events, "baz").io?.["1"].kind).toBe("inherited");
  expect(called.fileAccesses![0].path).toBeNull();
});

test("every open is retained while effective stdin and stdout use the last binding", () => {
  const result = analyze("foo <first <second >third >>fourth");
  expect(result.fileAccesses!.map((request) => [request.operation, request.effect, request.path])).toEqual([
    ["read", "read", "/workspace/first"],
    ["read", "read", "/workspace/second"],
    ["write", "truncate", "/workspace/third"],
    ["write", "append", "/workspace/fourth"],
  ]);
  expect(named(result.events, "foo").io).toMatchObject({
    0: { kind: "file", path: { kind: "known", value: "second" } },
    1: { kind: "file", path: { kind: "known", value: "fourth" }, mode: "append" },
  });
});

test("descriptor duplication order is significant and never opens a numeric filename", () => {
  const before = analyze("foo 2>&1 >out");
  const after = analyze("foo >out 2>&1");
  expect(named(before.events, "foo").io?.["2"]).toEqual({ kind: "inherited", descriptor: 1 });
  expect(named(after.events, "foo").io?.["2"]).toEqual(named(after.events, "foo").io?.["1"]);
  for (const result of [before, after])
    expect(result.fileAccesses!.map((request) => request.path)).toEqual(["/workspace/out"]);
  expect(analyze("foo 3>&1").fileAccesses).toHaveLength(0);
  expect(analyze("foo >out 3<&0").fileAccesses).toHaveLength(1);
});

test("combined stdout/stderr redirect aliases have the same file effects", () => {
  for (const source of ["foo &>out", "foo >&out", 'foo >&"out"', 'foo >&"$TARGET"']) {
    const result = analyze(source, [allow], { TARGET: "out" });
    expect(
      result.fileAccesses!.map((request) => request.path),
      source,
    ).toEqual(["/workspace/out"]);
    expect(named(result.events, "foo").io?.["1"], source).toEqual(named(result.events, "foo").io?.["2"]);
  }
});

test("here-strings are visible redirects with effective input, not input-path requests", () => {
  for (const source of [
    'foo <<<"payload"',
    '<<<"payload" foo',
    'env foo <<<"payload"',
    'f(){ foo; }; f <<<"payload"',
  ]) {
    const result = analyze(source);
    expect(result.fileAccesses, source).toHaveLength(0);
    expect(named(result.events, "foo").io?.["0"], source).toEqual({
      kind: "here-string",
      content: { kind: "known", value: "payload\n" },
    });
    expect(
      named(result.events, "foo").redirects.some((redirect) => redirect.kind === "here-string"),
      source,
    ).toBeTrue();
    expect(result.decision, source).toBe("allow");
  }
  const guard: ValidatedBashPolicy = {
    ...allow,
    layer: "guard",
    evaluate: (event) =>
      event.kind === "invocation" && event.redirects.length > 0
        ? { kind: "deny", reason: [{ kind: "literal", value: "redirect guard" }] }
        : { kind: "ignore" },
  };
  expect(analyze('foo <<<"payload"', [allow, guard]).decision).toBe("deny");
});

test("pipes and process substitutions cover both invocations without harness file checks", () => {
  for (const source of ["foo | bar", "foo <(bar)", "foo >(bar)", "foo < <(bar)"]) {
    const result = analyze(source);
    expect(named(result.events, "foo"), source).toBeDefined();
    expect(named(result.events, "bar"), source).toBeDefined();
    expect(result.fileAccesses, source).toHaveLength(0);
  }
  const pipeline = analyze("foo | bar");
  expect(named(pipeline.events, "foo").io?.["0"].kind).toBe("inherited");
  expect(named(pipeline.events, "bar").io?.["0"].kind).toBe("pipeline");
  expect(analyze("foo | bar >out").fileAccesses).toHaveLength(1);
});

test("unknown inline input remains explicit and substitutions retain invocation coverage", () => {
  const result = analyze('foo <<<"$(bar)"');
  expect(named(result.events, "bar")).toBeDefined();
  expect(named(result.events, "foo").io?.["0"]).toMatchObject({
    kind: "here-string",
    content: { kind: "unknown", reason: { kind: "command-substitution" } },
  });
  expect(result.fileAccesses).toHaveLength(0);
  expect(analyze('foo <<<"$INPUT"').events[0]).toMatchObject({
    io: { 0: { content: { kind: "known", value: "\n" } } },
  });
  const unknown = analyzeBashWithPolicies({
    source: 'foo <<<"$INPUT"',
    policies: [allow],
    initialEnvironment: { kind: "unavailable" },
  });
  expect(named(unknown.events, "foo").io?.["0"]).toMatchObject({ content: { kind: "unknown" } });
});

test("unsupported redirect grammar, heredocs, dynamic descriptors and special paths cannot auto-allow", async () => {
  for (const source of [
    "X=1 >out; foo",
    "foo 3<>out",
    "foo <<EOF\n$(bar)\nEOF\n",
    "foo 2>&$FD",
    "foo > /dev/tcp/example.test/80",
    "foo > /proc/self/fd/1",
    "foo > /workspace/../dev/tcp/example.test/80",
    "exec >out; foo",
    "readonly X=1; X=2 foo >out",
    "for item in one; do foo; done >out",
  ]) {
    const result = analyze(source);
    expect((await checkBashFilePermissions(result, { check: () => "allow" })).decision, source).toBe("defer");
  }
});

test("/dev/null requires harness permission for every read and write", async () => {
  for (const [operator, operation, effect] of [
    ["<", "read", "read"],
    [">", "write", "truncate"],
    [">>", "write", "append"],
    ["2>", "write", "truncate"],
    ["&>", "write", "truncate"],
  ] as const) {
    const source = `foo ${operator}/dev/null`;
    const result = analyze(source);
    expect(result.decision, source).toBe("defer");
    expect(result.fileAccesses, source).toHaveLength(1);
    expect(result.fileAccesses![0], source).toMatchObject({ path: "/dev/null", operation, effect });
    for (const [permission, expected] of [
      ["allow", "allow"],
      ["ask", "defer"],
      ["deny", "deny"],
    ] as const) {
      expect(
        (await checkBashFilePermissions(result, { check: () => permission })).decision,
        `${source}: ${permission}`,
      ).toBe(expected);
    }
  }
  expect(analyze("foo >/dev/./null").fileAccesses![0].path).toBe("/dev/./null");
});

test("directory changes cannot authorize relative files using stale startup cwd", async () => {
  for (const source of [
    "cd /elsewhere; foo >out",
    "pushd /elsewhere; foo >out",
    "f(){ cd /elsewhere; }; f; foo >out",
  ]) {
    const result = analyze(source);
    expect(result.fileAccesses![0], source).toMatchObject({ path: null, reason: "unknown-cwd" });
    expect((await checkBashFilePermissions(result, { check: () => "allow" })).decision, source).toBe("defer");
  }
  expect(analyze("( cd /elsewhere ); foo >out").fileAccesses![0].path).toBe("/workspace/out");
});

test("file denies dominate defers, failed checks defer, and command denies do not ask for file permission", async () => {
  const result = analyze("foo >first >second");
  expect(
    (
      await checkBashFilePermissions(result, {
        check: (request) => (request.path?.endsWith("second") ? "deny" : "ask"),
      })
    ).decision,
  ).toBe("deny");
  expect(
    (
      await checkBashFilePermissions(result, {
        check: () => {
          throw new Error("unavailable");
        },
      })
    ).decision,
  ).toBe("defer");
  let checked = 0;
  const denied = analyze("foo >out", [{ ...allow, evaluate: () => ({ kind: "deny", reason: [] }) }]);
  expect(
    (
      await checkBashFilePermissions(denied, {
        check: () => {
          checked++;
          return "allow";
        },
      })
    ).decision,
  ).toBe("deny");
  expect(checked).toBe(0);
});

test("v2 policies can condition command approval on inline content or trusted effective file input", async () => {
  const when = {
    any: [
      {
        all: [
          { call: "descriptorSourceIs", args: ["0", "here-string"] },
          { call: "descriptorContentIsKnown", args: ["0"] },
          { call: "equals", args: [{ call: "descriptorContent", args: ["0"] }, "accepted\n"] },
        ],
      },
      {
        all: [
          { call: "descriptorSourceIs", args: ["0", "file"] },
          { call: "equals", args: [{ call: "descriptorPath", args: ["0"] }, "trusted.yaml"] },
          { call: "equals", args: [{ ref: "event.cwd" }, "/workspace"] },
        ],
      },
    ],
  };
  const policy = createDslPolicy(
    compilePolicyDocument(
      validatePolicyDocument({
        language: "safety-core/bash-policy-v2",
        layer: "permission",
        select: [{ kind: "invocation" }],
        start: "start",
        states: {
          start: {
            cases: [{ when, action: { decision: "allow", reason: ["trusted input"] } }],
            default: { decision: "defer" },
            end: { decision: "defer" },
          },
        },
      }),
    ),
    "/stdin.policy.json",
  ) as ValidatedBashPolicy;
  for (const [source, expected] of [
    ['foo <<<"accepted"', "allow"],
    ['foo <<<"different"', "defer"],
    ['foo <<<"$(bar)"', "defer"],
    ["foo -f -", "defer"],
    ["foo -f - <trusted.yaml", "allow"],
    ["foo -f - <untrusted.yaml <trusted.yaml", "allow"],
  ] as const) {
    expect((await checkBashFilePermissions(analyze(source, [policy]), { check: () => "allow" })).decision, source).toBe(
      expected,
    );
  }
  expect(() =>
    validatePolicyDocument({
      language: "safety-core/bash-policy-v1",
      layer: "permission",
      select: [{ kind: "invocation" }],
      start: "start",
      states: {
        start: {
          cases: [{ when, action: { decision: "allow", reason: ["unsupported"] } }],
          default: { decision: "defer" },
          end: { decision: "defer" },
        },
      },
    }),
  ).toThrow();
});

test("property: generated here-string quoting and unquoted variable input agree with Bash", () => {
  const pieces = ["", "a b", "*?[abc]", "{x,y}", "'", '"', "\\", "$HOME", "\n", "é"];
  for (let seed = 0; seed < 100; seed++) {
    const value = pieces[seed % pieces.length]! + pieces[Math.floor(seed / pieces.length)]!;
    for (const word of [`'${value.replaceAll("'", "'\\''")}'`, "$VALUE", '"$VALUE"']) {
      const source = `cat <<<${word}`;
      const shell = spawnSync("bash", ["--noprofile", "--norc", "-c", source], {
        encoding: "utf8",
        env: { PATH: process.env.PATH ?? "", VALUE: value },
      });
      expect(shell.status, `seed ${seed}: ${word}`).toBe(0);
      expect(
        named(analyze(source, [allow], { VALUE: value }).events, "cat").io?.["0"],
        `seed ${seed}: ${word}`,
      ).toEqual({ kind: "here-string", content: { kind: "known", value: shell.stdout } });
    }
  }
  for (const word of ["$'a\\nb'", "$'a\\\"b'", "$'a\\\\b'", "$'a\\0b'", "$'\\x41\\101'"]) {
    const source = `cat <<<${word}`;
    const shell = spawnSync("bash", ["--noprofile", "--norc", "-c", source], { encoding: "utf8" });
    expect(named(analyze(source).events, "cat").io?.["0"], word).toEqual({
      kind: "here-string",
      content: { kind: "known", value: shell.stdout },
    });
  }
});

test("property: redirect placement preserves all file checks, while destination ordering preserves shell effects", async () => {
  for (let seed = 0; seed < 64; seed++) {
    const path = `file-${seed}`;
    for (const source of [
      `foo argument >${path}`,
      `>${path} foo argument`,
      `foo >${path} argument`,
      `{ foo argument; } >${path}`,
    ]) {
      const checked: HarnessFileAccessRequest[] = [];
      const result = await checkBashFilePermissions(analyze(source), {
        check: (request) => {
          checked.push(request);
          return "allow";
        },
      });
      expect(result.decision, source).toBe("allow");
      expect(
        checked.map((request) => request.path),
        source,
      ).toEqual([`/workspace/${path}`]);
      expect(named(result.events, "foo").argv, source).toEqual([{ kind: "known", value: "argument" }]);
    }
  }
});

test("argv-declared files remain outside harness redirect authorization", () => {
  expect(analyze("kubectl apply -f trusted.yaml").fileAccesses).toHaveLength(0);
  expect(parseBashProgram('foo <<<"payload"')).toMatchObject({
    statements: [{ redirects: [{ kind: "here-string", target: null, content: { text: '"payload"' } }] }],
  });
});
