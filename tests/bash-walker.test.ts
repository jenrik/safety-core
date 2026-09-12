import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";
import type { BashFunction, BashProgram } from "../src/bash/cst.ts";
import type { NormalizedCommand, ResolvedWord } from "../src/bash/expand.ts";
import { fromInitialEnvironment, lookupBinding } from "../src/bash/environment.ts";
import { safe } from "../src/bash/outcome.ts";
import { runSteps } from "../src/bash/runner.ts";
import { walkProgram } from "../src/bash/walker.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-walker-"));

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

describe("stateful Bash statement walker", () => {
  test("uses caller bindings for same-command words while discarding external-command prefix overlays", () => {
    const result = analyze("X=outer; X=prefix echo \"$X\"; echo \"$X\"");

    expect(argvs(result.invocations)).toEqual([["outer"], ["outer"]]);
  });

  test("uses dynamic function lookup, local shadows, and function-local prefix overlays", () => {
    const result = analyze("X=outer; f(){ local X=inner; echo \"$X\"; }; X=prefix f; echo \"$X\"");

    expect(argvs(result.invocations)).toEqual([["inner"], ["outer"]]);
  });

  test("propagates non-local function writes and stops only the function body on return", () => {
    const result = analyze("X=before; f(){ X=after; return; echo never; }; f; echo \"$X\"");

    expect(argvs(result.invocations)).toEqual([["after"]]);
  });

  test("models export, readonly, unset, and read without executing builtins", () => {
    const result = analyze("export X=one; readonly X; read INPUT; unset X; echo \"$X\" \"$INPUT\"");
    const invocation = result.invocations.at(-1)!;

    expect(invocation.executable).toEqual({ kind: "known", value: "echo" });
    expect(invocation.argv).toEqual([{ kind: "known", value: "one" }, unknownWord()]);
    expect(lookupBinding(invocation.environment, "X")).toMatchObject({
      value: { kind: "known", value: "one" },
      exported: true,
      readonly: true,
    });
  });

  test("persists prefix assignments only for modeled special builtins", () => {
    const result = analyze("X=prefix export X; echo \"$X\"");
    const invocation = result.invocations[0]!;

    expect(argvs(result.invocations)).toEqual([["prefix"]]);
    expect(lookupBinding(invocation.environment, "X")).toMatchObject({
      value: { kind: "known", value: "prefix" },
      exported: true,
    });
  });

  test("reports source-provenanced indeterminate evidence and taints state for eval and source", () => {
    for (const source of ["X=known; eval \"$PAYLOAD\"; echo \"$X\"", "X=known; source \"$FILE\"; echo \"$X\""]) {
      const result = analyze(source);
      const evidence = result.completed.evidence.find((outcome) => outcome.kind === "indeterminate");

      expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(argvs(result.invocations).at(-1)).toEqual(["<unknown>"]);
      expect(evidence).toMatchObject({ kind: "indeterminate", span: { start: 9 } });
    }
  });

  test("retains brace-group writes and isolates subshell and pipeline-child writes", () => {
    const grouped = analyze("X=outer; { X=group; }; echo \"$X\"");
    const isolated = analyze("X=outer; ( X=subshell; echo \"$X\" ); echo \"$X\"");
    const pipeline = analyze("X=outer; { X=left; echo \"$X\"; } | echo \"$X\"; echo \"$X\"");

    expect(argvs(grouped.invocations)).toEqual([["group"]]);
    expect(argvs(isolated.invocations)).toEqual([["subshell"], ["outer"]]);
    expect(argvs(pipeline.invocations)).toEqual([["left"], ["outer"], ["outer"]]);
  });

  test("merges all reachable conditional continuations before following statements", () => {
    const result = analyze("X=start; if condition; then X=left; else X=right; fi; echo \"$X\"");

    expect(argvs(result.invocations)).toEqual([[], ["<unknown>"]]);
  });

  test("retains every reachable function definition across a conditional join", () => {
    const result = analyze("if condition; then f(){ echo then; }; else f(){ echo else; }; fi; f");

    expect(argvs(result.invocations)).toEqual(expect.arrayContaining([["then"], ["else"]]));
  });

  test("taints unsupported arbitrary mutation while still walking nested statements and following commands", () => {
    const result = analyze("X=known; for item in one; do echo nested; done; echo \"$X\"");

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(argvs(result.invocations)).toEqual(expect.arrayContaining([["nested"], ["<unknown>"]]));
  });

  test("reports recursive function analysis through the function-depth budget without using the JS stack", () => {
    const result = analyze("f(){ f; }; f", { maxFunctionDepth: 3, maxSteps: 100 });

    expect(result.completed.outcome).toMatchObject({
      kind: "failure",
      reason: "analysis-failure",
      budget: "max-function-depth",
    });
  });

  test("bounds internal statement work with the environment's step and nested-script budgets", () => {
    const steps = analyze("echo first; echo second", {}, fromInitialEnvironment({}, { steps: 1 }));
    const nested = analyze("( echo child )", {}, fromInitialEnvironment({}, { nestedScriptDepth: 0 }));

    expect(steps.completed.outcome).toMatchObject({ kind: "failure", budget: "max-steps" });
    expect(nested.completed.outcome).toMatchObject({ kind: "failure", budget: "max-nested-script-depth" });
    expect(analyze("echo \"$(child)\"", {}, fromInitialEnvironment({}, { nestedScriptDepth: 0 })).completed.outcome)
      .toMatchObject({ kind: "failure", budget: "max-nested-script-depth" });
  });

  test("walks command substitutions and redirects before the enclosing dispatch", () => {
    for (const source of ["echo \"$(denied-command)\"", "echo ok >\"$(denied-command)\""]) {
      const result = analyzeWith(source, denyNamedCommand);

      expect(result.completed.verdict, source).toMatchObject({ kind: "deny" });
      expect(result.invocations.map((invocation) => invocation.executable)).toEqual([
        { kind: "known", value: "denied-command" },
      ]);
    }
  });

  test("walks retained redirect substitutions on every compound statement before its body", () => {
    for (const source of [
      "{ outer; } >\"$(denied-command)\"",
      "( outer ) >\"$(denied-command)\"",
      "outer | { next; } >\"$(denied-command)\"",
      "if condition; then outer; fi >\"$(denied-command)\"",
      "outer && { next; } >\"$(denied-command)\"",
      "for item in one; do outer; done >\"$(denied-command)\"",
    ]) {
      expect(analyzeWith(source, denyNamedCommand).completed.verdict, source).toMatchObject({ kind: "deny" });
    }
  });

  test("walks retained redirect substitutions on function CST statements", () => {
    const parsed = parseBashProgram("f(){ outer; }");
    expect(parsed.kind).toBe("program");
    if (parsed.kind !== "program") throw new Error(parsed.reason);
    const functionStatement = parsed.statements[0] as BashFunction;
    const denied = {
      kind: "command" as const,
      assignments: [],
      words: [{ kind: "word" as const, text: "denied-command", span: { start: 0, end: 14 } }],
      redirects: [],
      span: { start: 0, end: 14 },
    };
    const program: BashProgram = {
      ...parsed,
      statements: [{
        ...functionStatement,
        redirects: [{
          kind: "output",
          target: { kind: "command-substitution", text: "$(denied-command)", statements: [denied], span: { start: 0, end: 17 } },
          words: [{ kind: "command-substitution", text: "$(denied-command)", statements: [denied], span: { start: 0, end: 17 } }],
          span: { start: 0, end: 17 },
        }],
      }],
    };

    expect(analyzeProgram(program, denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("keeps an outer command neutral when a fully walked nested word still has unknown output", () => {
    expect(analyze("echo \"$(safe-command)\"").completed.verdict).toEqual({ kind: "neutral" });
  });

  test("gives injected dispatchers continuation and nested-script depth for transparent shell routes", () => {
    for (const source of [
      "command denied-command",
      "builtin eval denied-command",
      "eval 'denied-command'",
      ". 'denied-command'",
      "source 'denied-command'",
      "bash -c 'denied-command'",
    ]) {
      const result = analyzeWith(source, (request) => {
        const executable = request.command.executable;
        if (executable?.kind === "known" && executable.value === "denied-command") return denyAt(request);
        const script = knownArgument(request.command, executable?.kind === "known"
          ? executable.value === "builtin" || executable.value === "bash" ? 1 : 0
          : false);
        return script ? request.continueWith(script) : safe();
      });

      expect(result.completed.verdict, source).toMatchObject({ kind: "deny" });
      expect(result.depths.some((depth) => depth > 0)).toBeTrue();
    }
  });

  test("defaults callback continuation state to the normalized command-prefix environment", () => {
    const result = analyzeWith("TARGET=safe; TARGET=denied bash -c 'run \"$TARGET\"'", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "bash") {
        const script = knownArgument(request.command, 1);
        return script ? request.continueWith(script) : safe();
      }
      return request.command.executable?.kind === "known" && request.command.executable.value === "run"
        && knownArgument(request.command, 0) === "denied"
        ? denyAt(request)
        : safe();
    });

    expect(result.completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("lets eval and source continuations select caller-state rather than subshell isolation", () => {
    for (const source of ["eval 'X=inner'; echo \"$X\"", "source 'X=inner'; echo \"$X\""]) {
      const result = analyzeWith(source, (request) => {
        const executable = request.command.executable;
        if (executable?.kind === "known" && ["eval", "source"].includes(executable.value)) {
          const script = knownArgument(request.command, 0);
          return script ? request.continueWith(script, undefined, { isolate: false }) : safe();
        }
        return safe();
      }, fromInitialEnvironment({ X: "outer" }));

      expect(argvs(result.invocations).at(-1)).toEqual(["inner"]);
    }
  });

  test("confines return to the active function and preserves non-returning branch continuations", () => {
    for (const source of [
      "return; denied-command",
      "f(){ ( return; echo skipped ); denied-command; }; f",
      "f(){ if condition; then return; else :; fi; denied-command; }; f",
    ]) {
      expect(analyzeWith(source, denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    }
  });

  test("preserves loop zero and repeated-write uncertainty", () => {
    const result = analyze("X=unsafe; while condition; do X=safe; done; run \"$X\"");

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("taints state after unmodelled state-mutating builtins", () => {
    const result = analyze("X=old; printf -v X new; run \"$X\"");

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("taints stale state after wait writes through -p", () => {
    const result = analyze("X=safe; wait -p X; run \"$X\"");

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("taints caller state when builtin routes an unresolved eval payload", () => {
    const result = analyze("X=old; builtin eval \"$UNKNOWN\"; run \"$X\"");

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("merges every non-isolated callback continuation environment", () => {
    const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "route") {
        const left = request.continueWith("X=left", undefined, { isolate: false });
        const right = request.continueWith("X=right", undefined, { isolate: false });
        return { outcome: safe(), continuations: [...continuationsOf(left), ...continuationsOf(right)] };
      }
      return safe();
    });

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("keeps explicit non-isolated replacement environments from producing a total safe result", () => {
    const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "route") {
        const left = request.continueWith(":", fromInitialEnvironment({ X: "left" }), { isolate: false });
        const right = request.continueWith(":", fromInitialEnvironment({ X: "right" }), { isolate: false });
        return { outcome: safe(), continuations: [...continuationsOf(left), ...continuationsOf(right)] };
      }
      return safe();
    });

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
  });

  test("property: default non-isolated continuation permutations process every branch and merge divergent writes", () => {
    const random = lcg(0x51a7e5ed);

    for (let iteration = 0; iteration < 64; iteration++) {
      const fanout = 2 + (random() % 4);
      const labels = Array.from({ length: fanout }, (_unused, index) => `branch-${iteration}-${index}-${random()}`);
      const orders = [
        labels,
        [...labels].reverse(),
        permutation(labels, random),
      ];

      for (const order of orders) {
        const processed: string[] = [];
        const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
          const executable = request.command.executable;
          if (executable?.kind === "known" && executable.value === "route") {
            return {
              outcome: safe(),
              continuations: order.flatMap((label) => continuationsOf(
                request.continueWith(`X=${label}; branch ${label}`, undefined, { isolate: false }),
              )),
            };
          }
          if (executable?.kind === "known" && executable.value === "branch") {
            const label = knownArgument(request.command, 0);
            if (label) processed.push(label);
          }
          return safe();
        });

        expect(processed.sort()).toEqual([...labels].sort());
        expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
        expect(result.completed.verdict).toEqual({ kind: "neutral" });
      }
    }
  });

  test("property: explicit non-isolated replacement environments fail closed before execution", () => {
    const random = lcg(0x76a5b4c3);

    for (let iteration = 0; iteration < 64; iteration++) {
      const fanout = 2 + (random() % 4);
      const labels = Array.from({ length: fanout }, (_unused, index) => `replacement-${iteration}-${index}-${random()}`);
      const processed: string[] = [];
      const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
        const executable = request.command.executable;
        if (executable?.kind === "known" && executable.value === "route") {
          return {
            outcome: safe(),
            continuations: permutation(labels, random).flatMap((label) => continuationsOf(
              request.continueWith(`replacement-branch ${label}`, fromInitialEnvironment({ X: label }), { isolate: false }),
            )),
          };
        }
        if (executable?.kind === "known" && executable.value === "replacement-branch") {
          const label = knownArgument(request.command, 0);
          if (label) processed.push(label);
        }
        return safe();
      });

      expect(processed).toEqual([]);
      expect(result.completed.verdict).toEqual({ kind: "neutral" });
    }
  });

  test("property: generated compound redirect placement never skips an inner deny", () => {
    const random = lcg(0x9e3779b9);
    const templates = [
      (name: string) => `{ ${name}; } >\"$(denied-command)\"`,
      (name: string) => `( ${name} ) >\"$(denied-command)\"`,
      (name: string) => `${name} | { next; } >\"$(denied-command)\"`,
      (name: string) => `if condition; then ${name}; fi >\"$(denied-command)\"`,
      (name: string) => `${name} && { next; } >\"$(denied-command)\"`,
      (name: string) => `for item in one; do ${name}; done >\"$(denied-command)\"`,
    ];

    for (let iteration = 0; iteration < 96; iteration++) {
      const source = templates[random() % templates.length]!(`outer_${iteration}_${random()}`);
      expect(analyzeWith(source, denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    }
  });

  test("makes local declarations shadow before later assignment and rejects readonly writes", () => {
    const local = analyze("X=outer; f(){ local X; X=inner; echo \"$X\"; }; f; echo \"$X\"");
    const readonly = analyze("X=old; readonly X; X=new; unset X; echo \"$X\"");

    expect(argvs(local.invocations)).toEqual([["inner"], ["outer"]]);
    expect(argvs(readonly.invocations)).toEqual([["old"]]);
  });

  test("taints the possible write scope for read options rather than a consumed option operand", () => {
    const result = analyze("X=old; read -p prompt X; run \"$X\"");

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("property: repeated function calls retain distinct caller bindings and never leak locals", () => {
    const random = lcg(0x8badf00d);

    for (let iteration = 0; iteration < 64; iteration++) {
      const first = `first-${random()}`;
      const second = `second-${random()}`;
      const result = analyze(`X=${first}; f(){ local LOCAL=inside; echo \"$X\" \"$LOCAL\"; }; f; X=${second}; f; echo \"$LOCAL\"`);

      expect(argvs(result.invocations)).toEqual([
        [first, "inside"],
        [second, "inside"],
        ["<unknown>"],
      ]);

      const recursive = analyze("f(){ f; }; f", { maxFunctionDepth: 2, maxSteps: 100 });
      expect(recursive.completed.outcome).toMatchObject({
        kind: "failure",
        reason: "analysis-failure",
        budget: "max-function-depth",
      });
    }
  });
});

function analyze(
  source: string,
  limits: Parameters<typeof runSteps>[1] = {},
  environment = fromInitialEnvironment(),
) {
  return analyzeWith(source, (request) => {
    const invocation = request.command;
    return safe();
  }, environment, limits);
}

interface DispatchRequestLike {
  readonly command: NormalizedCommand;
  readonly nestedScriptDepth: number;
  readonly continueWith: (source: string, environment?: ReturnType<typeof fromInitialEnvironment>, options?: { readonly isolate?: boolean }) => unknown;
}

function analyzeWith(
  source: string,
  dispatch: (request: DispatchRequestLike) => unknown,
  environment = fromInitialEnvironment(),
  limits: Parameters<typeof runSteps>[1] = {},
) {
  const program = parseBashProgram(source);
  expect(program.kind).toBe("program");
  if (program.kind !== "program") throw new Error(program.reason);

  return analyzeProgram(program, dispatch, environment, limits);
}

function analyzeProgram(
  program: BashProgram,
  dispatch: (request: DispatchRequestLike) => unknown,
  environment = fromInitialEnvironment(),
  limits: Parameters<typeof runSteps>[1] = {},
) {
  const invocations: NormalizedCommand[] = [];
  const depths: number[] = [];
  const initial = walkProgram(program, {
    environment,
    dispatchCommand: (request) => {
      const candidate = request as unknown as DispatchRequestLike;
      invocations.push(candidate.command ?? request as unknown as NormalizedCommand);
      depths.push(candidate.nestedScriptDepth ?? 0);
      return dispatch(candidate) as ReturnType<typeof safe>;
    },
  });
  return {
    invocations,
    depths,
    completed: runSteps(initial, { maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 10_000, maxWorkItems: 10_000, ...limits }),
  };
}

function denyNamedCommand(request: DispatchRequestLike) {
  return request.command.executable?.kind === "known" && request.command.executable.value === "denied-command"
    ? denyAt(request)
    : safe();
}

function denyAt(_request: DispatchRequestLike) {
  return { kind: "deny", span: { start: 0, end: 0 } } as const;
}

function knownArgument(command: NormalizedCommand, index: number | false): string | undefined {
  if (index === false) return undefined;
  const argument = command.argv[index];
  return argument?.kind === "known" ? argument.value : undefined;
}

function continuationsOf(result: unknown): readonly unknown[] {
  if (!result || typeof result !== "object" || !("continuations" in result)) return [];
  const continuations = (result as { continuations?: unknown }).continuations;
  return Array.isArray(continuations) ? continuations : [];
}

function argvs(invocations: readonly NormalizedCommand[]): string[][] {
  return invocations.map((invocation) => invocation.argv.map(renderWord));
}

function renderWord(word: ResolvedWord): string {
  return word.kind === "known" ? word.value : "<unknown>";
}

function unknownWord(): ResolvedWord {
  return expect.objectContaining({ kind: "unknown" }) as unknown as ResolvedWord;
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function permutation<T>(values: readonly T[], random: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index--) {
    const other = random() % (index + 1);
    [result[index], result[other]] = [result[other]!, result[index]!];
  }
  return result;
}
