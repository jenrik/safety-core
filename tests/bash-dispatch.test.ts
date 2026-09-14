import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";
import {
  createCommandRegistry,
  dispatchCommand,
  type CommandHandler,
  type InvocationCursor,
} from "../src/bash/dispatch.ts";
import { fromInitialEnvironment, unknown } from "../src/bash/environment.ts";
import { httpHandlers } from "../src/bash/handlers/http.ts";
import { readerHandlers } from "../src/bash/handlers/readers.ts";
import { safe } from "../src/bash/outcome.ts";
import { runSteps } from "../src/bash/runner.ts";
import { structuralHandlers } from "../src/bash/handlers/registry.ts";
import { HTTP_TOOLS, READING_COMMANDS } from "../src/patterns.ts";
import { type BashDispatchRequest, type BashDispatchResult, walkProgram } from "../src/bash/walker.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-dispatch-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(
    join(process.cwd(), "node_modules", "web-tree-sitter"),
    join(wasmDir, "node_modules", "web-tree-sitter"),
  );
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("named Bash command dispatch", () => {
  test("routes a strace child to only the registered executable handler", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("strace -f gh pr create --repo github.com/acme/widgets", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations).toHaveLength(1);
    expect(invocations[0]).toMatchObject({
      invocation: {
        executable: { kind: "known", value: "gh" },
        argv: [
          { kind: "known", value: "pr" },
          { kind: "known", value: "create" },
          { kind: "known", value: "--repo" },
          { kind: "known", value: "github.com/acme/widgets" },
        ],
      },
      index: 0,
    });
  });

  test("gives every named handler a frozen cursor and frozen options", () => {
    let cursor: InvocationCursor | undefined;
    const result = analyze("gh pr create", [recordingHandler("gh", [], (received) => { cursor = received; })]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(cursor).toBeDefined();
    expect(Object.isFrozen(cursor)).toBeTrue();
    expect(Object.isFrozen(cursor?.invocation)).toBeTrue();
    expect(Object.isFrozen(cursor?.options)).toBeTrue();
  });

  test("registers only structural handlers by default", () => {
    const registry = createCommandRegistry();

    expect(registry.resolve("env").name).toBe("env");
    expect(registry.resolve("sh").name).toBe("sh");
    expect(registry.resolve("cat").name).toBe("unknown-command");
    expect(registry.resolve("curl").name).toBe("unknown-command");
    expect(registry.resolve("gh").name).toBe("unknown-command");
  });

  test("property: every structural handler is resolved by the default registry", () => {
    const registry = createCommandRegistry();
    for (const handler of structuralHandlers) {
      expect(registry.resolve(handler.name).name).toBe(handler.name);
    }
  });

  test("property: command-policy facades cover exactly their configured command sets", () => {
    expect(new Set(readerHandlers.map((handler) => handler.name))).toEqual(READING_COMMANDS);
    expect(new Set(httpHandlers.map((handler) => handler.name))).toEqual(HTTP_TOOLS);
  });

  test("composes a caller policy handler with mandatory wrapper recursion", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("strace -f denied-command", [
      recordingHandler("strace", invocations),
      denyHandler("denied-command"),
    ]);

    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
    expect(invocations).toHaveLength(1);
    expect(invocations[0]?.invocation.executable).toEqual({ kind: "known", value: "strace" });
  });

  test.each([
    ["env -i MODE=test gh pr create", "gh", ["pr", "create"]],
    ["command -p gh pr create", "gh", ["pr", "create"]],
    ["doas -n -u root gh pr create", "gh", ["pr", "create"]],
    ["exec -a check gh pr create", "gh", ["pr", "create"]],
    ["nice -n 5 gh pr create", "gh", ["pr", "create"]],
    ["nice -n5 gh pr create", "gh", ["pr", "create"]],
    ["nohup -- gh pr create", "gh", ["pr", "create"]],
    ["setsid --fork gh pr create", "gh", ["pr", "create"]],
    ["stdbuf -oL gh pr create", "gh", ["pr", "create"]],
    ["timeout -k 5s 10s gh pr create", "gh", ["pr", "create"]],
    ["strace -f -o trace.log gh pr create", "gh", ["pr", "create"]],
  ])("consumes supported wrapper flags before dispatching %s", (source, executable, argv) => {
    const invocations: InvocationCursor[] = [];
    const result = analyze(source, [recordingHandler(executable, invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations.map(renderInvocation)).toEqual([[executable, ...argv]]);
  });

  test("does not treat doas shell mode as a transparent child invocation", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("doas -s gh pr create", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(invocations).toHaveLength(0);
  });

  test("property: doas configuration checks never expose a child invocation", () => {
    const random = lcg(0x4fca_7e12);
    for (let iteration = 0; iteration < 64; iteration++) {
      const invocations: InvocationCursor[] = [];
      const flags = shuffle(["-n", "-u root"], random).join(" ");
      const result = analyze(`doas ${flags} -C config-${random()} gh pr create`, [recordingHandler("gh", invocations)]);

      expect(result.completed.verdict).toEqual({ kind: "allow" });
      expect(invocations).toHaveLength(0);
    }
  });

  test("keeps a doas configuration check with no config path neutral", () => {
    const result = directWrapperDispatch("doas", ["-C"]);

    expect(dispatchOutcome(result.result)).toMatchObject({ kind: "indeterminate" });
    expect(result.scheduled).toHaveLength(0);
  });

  test("walks a statically known sh -c script only through continueWith", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("sh -c 'gh pr create --repo github.com/acme/widgets'", [recordingHandler("gh", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations.map(renderInvocation)).toEqual([[
      "gh", "pr", "create", "--repo", "github.com/acme/widgets",
    ]]);
  });

  test("clears omitted positional parameters for sh -c beneath a function call", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("outer(){ sh -c 'run \"$1\" \"$2\"'; }; outer caller-one caller-two", [recordingHandler("run", invocations)]);

    expect(result.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations.map(renderInvocation)).toEqual([["run", "", ""]]);
  });

  test.each([
    "sh -xc denied-command",
    "sh -o xtrace -c denied-command",
  ])("walks %s rather than allowing a combined or value-taking shell option", (source) => {
    const result = analyze(source, [denyHandler("denied-command")]);

    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("returns neutral for an ambient sh -c script rather than treating it as an executable", () => {
    const result = analyze("sh -c '$COMMAND'", [], { COMMAND: unknown({ kind: "ambient" }) });

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
  });

  test("leaves an unregistered executable neutral through unknown-command", () => {
    const result = analyze("unregistered --write", []);

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(result.completed.evidence).toContainEqual({
      kind: "indeterminate",
      span: { start: 0, end: "unregistered --write".length },
    });
  });

  test("dispatches statically closed find -exec children but not xargs dynamic input", () => {
    const invocations: InvocationCursor[] = [];
    const find = analyze("find . -type f -exec gh pr create --repo github.com/acme/widgets \\;", [recordingHandler("gh", invocations)]);
    const xargs = analyze("xargs -n 1 gh pr create", [recordingHandler("gh", invocations)]);

    expect(find.completed.verdict).toEqual({ kind: "allow" });
    expect(invocations.map(renderInvocation)).toEqual([[
      "gh", "pr", "create", "--repo", "github.com/acme/widgets",
    ]]);
    expect(xargs.completed.verdict).toEqual({ kind: "neutral" });
  });

  test("walks every statically closed find -exec action", () => {
    const invocations: InvocationCursor[] = [];
    const result = analyze("find . -exec allowed-command \\; -exec denied-command \\;", [
      recordingHandler("allowed-command", invocations),
      denyHandler("denied-command"),
    ]);

    expect(invocations.map(renderInvocation)).toEqual([["allowed-command"]]);
    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("keeps nested indeterminacy and nested-depth failures sticky through wrapper chains", () => {
    const indeterminate = analyze("strace -f sh -c '$UNKNOWN'", [], { UNKNOWN: unknown({ kind: "ambient" }) });
    const exhausted = analyze("strace -f sh -c 'allowed-command'", [recordingHandler("allowed-command", [])], fromInitialEnvironment({}, {
      nestedScriptDepth: 0,
    }));

    expect(indeterminate.completed.verdict).toEqual({ kind: "neutral" });
    expect(exhausted.completed.outcome).toMatchObject({ kind: "failure", budget: "max-nested-script-depth" });
  });

  test("property: wrapper flag permutations preserve the same known child invocation", () => {
    const random = lcg(0x2c4d6e8f);
    const flags = ["-f", "-o trace.log", "-e trace=process"];

    for (let iteration = 0; iteration < 64; iteration++) {
      const invocations: InvocationCursor[] = [];
      const permutation = shuffle(flags, random);
      const result = analyze(`strace ${permutation.join(" ")} gh pr create`, [recordingHandler("gh", invocations)]);

      expect(result.completed.verdict).toEqual({ kind: "allow" });
      expect(invocations.map(renderInvocation)).toEqual([["gh", "pr", "create"]]);
    }
  });

  test("property: audited flags for every child-executing wrapper preserve its known child", () => {
    const random = lcg(0x4b1d7a2c);
    const wrappers = [
      { name: "env", prefix: "env", flags: ["-i", "MODE=test"], child: "gh pr create" },
      { name: "command", prefix: "command", flags: ["-p"], child: "gh pr create" },
      { name: "doas", prefix: "doas", flags: ["-n", "-u root"], child: "gh pr create" },
      { name: "exec", prefix: "exec", flags: ["-c", "-l", "-a name"], child: "gh pr create" },
      { name: "nice", prefix: "nice", flags: ["-n 5"], child: "gh pr create" },
      { name: "nohup", prefix: "nohup", flags: ["--"], child: "gh pr create" },
      { name: "setsid", prefix: "setsid", flags: ["--fork", "--wait"], child: "gh pr create" },
      { name: "stdbuf", prefix: "stdbuf", flags: ["-oL", "-e0"], child: "gh pr create" },
      { name: "timeout", prefix: "timeout", flags: ["-k 5s", "--foreground"], child: "10s gh pr create" },
      { name: "strace", prefix: "strace", flags: ["-f", "-o trace.log", "-e trace=process"], child: "gh pr create" },
      { name: "sh", prefix: "sh", flags: ["-x", "-v"], child: "-c 'gh pr create'" },
    ];

    for (const wrapper of wrappers) {
      for (let iteration = 0; iteration < 32; iteration++) {
        const invocations: InvocationCursor[] = [];
        const flags = shuffle(wrapper.flags, random).join(" ");
        const source = `${wrapper.prefix} ${flags} ${wrapper.child}`;
        const result = analyze(source, [recordingHandler("gh", invocations)]);

        expect(result.completed.verdict, `${wrapper.name}: ${source}`).toEqual({ kind: "allow" });
        expect(invocations.map(renderInvocation), `${wrapper.name}: ${source}`).toEqual([["gh", "pr", "create"]]);
      }
    }
  });

  test("property: an unknown child word at every wrapper boundary is never allow", () => {
    const wrappers = [
      (child: string) => `env -i ${child}`,
      (child: string) => `command -p ${child}`,
      (child: string) => `doas -n -u root ${child}`,
      (child: string) => `exec -a name ${child}`,
      (child: string) => `nice -n 5 ${child}`,
      (child: string) => `nohup -- ${child}`,
      (child: string) => `setsid --fork ${child}`,
      (child: string) => `stdbuf -oL ${child}`,
      (child: string) => `timeout 1s ${child}`,
      (child: string) => `strace -f ${child}`,
      (child: string) => `sh -c ${child}`,
      (child: string) => `find . -exec ${child} \\;`,
    ];

    for (const wrapper of wrappers) {
      const baselineInvocations: InvocationCursor[] = [];
      const baseline = analyze(wrapper("gh"), [recordingHandler("gh", baselineInvocations)]);
      const result = analyze(wrapper('"$UNKNOWN"'), [recordingHandler("gh", [])], { UNKNOWN: unknown({ kind: "ambient" }) });

      expect(baseline.completed.verdict, wrapper.name).toEqual({ kind: "allow" });
      expect(baselineInvocations.map(renderInvocation), wrapper.name).toEqual([["gh"]]);
      expect(result.completed.verdict, wrapper.name).toEqual({ kind: "neutral" });
    }
  });

  test("property: direct wrapper results retain an unknown at every audited boundary before walker evidence", () => {
    const wrappers = [
      ["env", ["-i", "MODE=test", "gh"]],
      ["env", ["-u", "NAME", "gh"]],
      ["command", ["-p", "gh"]],
      ["doas", ["-n", "-u", "root", "gh"]],
      ["exec", ["-a", "name", "gh"]],
      ["nice", ["-n", "5", "gh"]],
      ["nohup", ["--", "gh"]],
      ["setsid", ["--fork", "gh"]],
      ["stdbuf", ["-oL", "gh"]],
      ["stdbuf", ["-o", "L", "gh"]],
      ["timeout", ["-k", "5s", "10s", "gh"]],
      ["strace", ["-f", "gh"]],
      ["strace", ["-o", "trace.log", "gh"]],
      ["sh", ["-c", "gh"]],
      ["find", [".", "-exec", "gh", ";"]],
    ] as const;

    for (const [executable, argv] of wrappers) {
      const baseline = directWrapperDispatch(executable, argv);
      expect(dispatchOutcome(baseline.result), executable).toEqual({ kind: "safe" });
      expect(baseline.scheduled, executable).toHaveLength(1);

      for (let boundary = 0; boundary < argv.length; boundary++) {
        const result = directWrapperDispatch(executable, [
          ...argv.slice(0, boundary),
          undefined,
          ...argv.slice(boundary),
        ]);
        expect(dispatchOutcome(result.result), `${executable}:${boundary}`).toMatchObject({ kind: "indeterminate" });
      }
    }
  });

  test("routes every registered executable name only to its matching caller handler", () => {
    const names = ["env", "command", "doas", "exec", "nice", "nohup", "setsid", "stdbuf", "timeout", "strace", "xargs", "find", "sh"];
    const invocations: InvocationCursor[] = [];
    const handlers = names.map((name) => recordingHandler(name, invocations));

    for (const name of names) analyze(name, handlers);

    expect(invocations.map((cursor) => cursor.invocation.executable)).toEqual(names.map((name) => ({ kind: "known", value: name })));
  });

  test("treats an empty known executable name as unknown-command", () => {
    const result = analyze('"$EMPTY"', [], fromInitialEnvironment({ EMPTY: "" }));

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
  });
});

function analyze(
  source: string,
  handlers: readonly CommandHandler[],
  environment = fromInitialEnvironment(),
) {
  const program = parseBashProgram(source);
  expect(program.kind).toBe("program");
  if (program.kind !== "program") throw new Error(program.reason);

  const registry = createCommandRegistry(handlers);
  const initial = walkProgram(program, {
    environment,
    dispatchCommand: (request) => dispatchCommand(request, registry),
  });
  return { completed: runSteps(initial) };
}

function recordingHandler(
  name: string,
  invocations: InvocationCursor[],
  onInvocation?: (cursor: InvocationCursor) => void,
): CommandHandler {
  return {
    name,
    handle(cursor) {
      invocations.push(cursor);
      onInvocation?.(cursor);
      return safe();
    },
  };
}

function denyHandler(name: string): CommandHandler {
  return {
    name,
    handle() {
      return { kind: "deny", span: { start: 0, end: 0 } };
    },
  };
}

function directWrapperDispatch(executable: string, argv: readonly (string | undefined)[]) {
  const environment = fromInitialEnvironment();
  const scheduled: string[] = [];
  const request: BashDispatchRequest = {
    command: {
      executable: { kind: "known", value: executable },
      argv: argv.map((value) => value === undefined
        ? { kind: "unknown", reason: { kind: "property", span: { start: 0, end: 0 } } }
        : { kind: "known", value }),
      redirects: [],
      environment,
      assignmentPatch: { environment, writes: new Set() },
    },
    span: { start: 0, end: 0 },
    environment,
    functionDepth: 0,
    nestedScriptDepth: 0,
    continueWith: (source) => {
      scheduled.push(source);
      return {
        outcome: safe(),
        continuations: [{
          source,
          environment,
          functionDepth: 0,
          nestedScriptDepth: 1,
          isolate: true,
          environmentExplicit: false,
        }],
      };
    },
  };
  return { result: dispatchCommand(request), scheduled };
}

function dispatchOutcome(result: BashDispatchResult) {
  return "kind" in result ? result : result.outcome;
}

function renderInvocation(cursor: InvocationCursor): string[] {
  const executable = cursor.invocation.executable;
  if (executable?.kind !== "known") throw new Error("expected known invocation executable");
  return [executable.value, ...cursor.invocation.argv.map((argument) => {
    if (argument.kind !== "known") throw new Error("expected known invocation argument");
    return argument.value;
  })];
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function shuffle<T>(values: readonly T[], random: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index--) {
    const other = random() % (index + 1);
    [result[index], result[other]] = [result[other]!, result[index]!];
  }
  return result;
}
