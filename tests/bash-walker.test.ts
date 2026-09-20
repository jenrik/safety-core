import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";
import type { BashFunction, BashProgram } from "../src/bash/cst.ts";
import { dispatchCommand, preflightCommand } from "../src/bash/dispatch.ts";
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

  test("preserves current-shell builtin writes through command", () => {
    const result = analyzeWith('command export X=inner; run "$X"', (request) => dispatchCommand(request as never));

    expect(argvs(result.invocations).at(-1)).toEqual(["inner"]);
  });

  test("expands known positional arguments in function bodies", () => {
    const functionCall = analyze("f(){ run \"$1\" \"$2\"; }; f function-one function-two");

    expect(argvs(functionCall.invocations)).toEqual([["function-one", "function-two"]]);
  });

  test("clears omitted positional parameters in nested function calls", () => {
    const result = analyze("outer(){ inner(){ run \"$1\" \"$2\"; }; inner; }; outer caller-one caller-two");

    expect(argvs(result.invocations)).toEqual([["", ""]]);
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

  test("applies unset function and variable modes to complete shell state", () => {
    expect(analyzeWith("f(){ denied-command; }; unset -f f; f", denyNamedCommand).completed.verdict).toEqual({ kind: "allow" });
    expect(analyzeWith("unset -v f; f(){ denied-command; }; unset -- f; f", denyNamedCommand).completed.verdict).toEqual({ kind: "allow" });
    expect(analyzeWith("f(){ denied-command; }; unset -v f; f", denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    expect(analyzeWith("f(){ denied-command; }; f=value; unset f; f", denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    expect(analyzeWith("f(){ denied-command; }; unset -fv f; f", denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("keeps unset scope and dynamic function removal conservative", () => {
    expect(analyzeWith("f(){ denied-command; }; { unset -f f; }; f", denyNamedCommand).completed.verdict).toEqual({ kind: "allow" });
    expect(analyzeWith("f(){ denied-command; }; (unset -f f); f", denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    expect(analyzeWith("f(){ denied-command; }; if condition; then unset -f f; fi; f", denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
    expect(analyzeWith('f(){ denied-command; }; unset -f "$UNKNOWN"; f', denyNamedCommand).completed.verdict).toMatchObject({ kind: "deny" });
  });

  test("property: unset -f option ordering removes only the named function", () => {
    for (let index = 0; index < 64; index++) {
      const options = index % 3 === 0 ? "-fn" : index % 3 === 1 ? "-nf" : "-f --";
      const source = `f_${index}(){ denied-command; }; keep_${index}(){ denied-command; }; unset ${options} f_${index}; f_${index}`;
      expect(analyzeWith(source, denyNamedCommand).completed.verdict, source).toEqual({ kind: "allow" });
    }
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

  test("preserves current-shell writes through a timed brace group", () => {
    const result = analyze('time { X=inner; }; run "$X"');
    const run = result.invocations.find((invocation) => invocation.executable?.kind === "known" && invocation.executable.value === "run");

    expect(run).toBeDefined();
    expect(argvs([run!])).toEqual([["inner"]]);
  });

  test("schedules a named coprocess subshell body exactly once", () => {
    const result = analyze("coproc worker_1 ( nested-coproc-body )");
    const nested = result.invocations.filter((invocation) =>
      invocation.executable?.kind === "known" && invocation.executable.value === "nested-coproc-body"
    );

    expect(nested).toHaveLength(1);
  });

  test("builds and schedules typed invocation children without source depth", () => {
    let child: unknown;
    const result = analyzeWith("route", (request) => {
      if (request.command.executable?.kind !== "known" || request.command.executable.value !== "route") return safe();
      const scheduled = request.continueWithInvocation([
        { kind: "known", value: "child" },
        { kind: "known", value: "MODE=1" },
      ], undefined, { processEffect: "spawn-async" });
      child = childrenOf(scheduled)[0];
      return scheduled;
    });

    expect(child).toMatchObject({
      target: {
        kind: "invocation",
        command: {
          executable: { kind: "known", value: "child" },
          argv: [{ kind: "known", value: "MODE=1" }],
        },
      },
      processEffect: "spawn-async",
      nestedScriptDepth: 0,
    });
    expect(result.invocations.map((invocation) => invocation.executable)).toEqual([
      { kind: "known", value: "route" },
      { kind: "known", value: "child" },
    ]);
    expect(result.depths).toEqual([0, 0]);
  });

  test("represents unsupported child execution with a redacted opaque reason", () => {
    let child: unknown;
    const result = analyzeWith("route opaque-canary", (request) => {
      if (request.command.executable?.kind !== "known" || request.command.executable.value !== "route") return safe();
      const scheduled = request.continueWithOpaque("unsupported-execution");
      child = childrenOf(scheduled)[0];
      return scheduled;
    });

    expect(child).toMatchObject({ target: { kind: "opaque", reason: "unsupported-execution" } });
    expect(result.completed.verdict).toEqual({ kind: "neutral" });
    expect(result.completed.outcome).toMatchObject({ kind: "failure", reason: "analysis-failure" });
    expect(JSON.stringify(child)).not.toContain("opaque-canary");
  });

  test("walks complete nested-source prefixes before failure and keeps denial dominant", () => {
    for (const nestedSource of ["allowed-command; if", "denied-command; if"] as const) {
      const result = analyzeWith("route", (request) => {
        if (request.command.executable?.kind === "known" && request.command.executable.value === "route") {
          return request.continueWithSource(nestedSource);
        }
        return denyNamedCommand(request);
      });

      expect(result.completed.outcome.kind, nestedSource).toBe(nestedSource.startsWith("denied") ? "deny" : "failure");
      expect(result.invocations.map((invocation) => invocation.executable), nestedSource).toContainEqual({
        kind: "known",
        value: nestedSource.startsWith("denied") ? "denied-command" : "allowed-command",
      });
    }
  });

  test("property: invocation targets consume work budgets but not source depth", () => {
    for (const depth of [1, 8, 32, 65]) {
      const source = `${"command ".repeat(depth)}leaf`;
      const exact = depth + 2;
      const completed = analyzeWith(source, (request) => dispatchCommand(request as never), fromInitialEnvironment({}, {
        nestedScriptDepth: 0,
        steps: exact,
        workItems: exact,
      }));
      const exhausted = analyzeWith(source, (request) => dispatchCommand(request as never), fromInitialEnvironment({}, {
        nestedScriptDepth: 0,
        steps: exact - 1,
        workItems: exact,
      }));

      expect(completed.completed.outcome.kind, `complete:${depth}`).not.toBe("failure");
      expect(completed.depths.every((value) => value === 0), `depth:${depth}`).toBeTrue();
      expect(exhausted.completed.outcome, `exhausted:${depth}`).toMatchObject({
        kind: "failure",
        budget: "max-steps",
      });
    }
  });

  test("merges all reachable conditional continuations before following statements", () => {
    const result = analyze("X=start; if condition; then X=left; else X=right; fi; echo \"$X\"");

    expect(argvs(result.invocations)).toEqual([[], ["<unknown>"]]);
  });

  test("retains every reachable function definition across a conditional join", () => {
    const result = analyze("if condition; then f(){ echo then; }; else f(){ echo else; }; fi; f");

    expect(argvs(result.invocations)).toEqual(expect.arrayContaining([["then"], ["else"]]));
  });

  test("keeps an unknown external-function possibility when a branch only conditionally defines it", () => {
    const result = analyze("if condition; then f(){ :; }; fi; f");

    expect(result.completed.verdict).toEqual({ kind: "neutral" });
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

  test("drains admitted internal work after maxWorkItems admission failure", () => {
    const admittedDeny = analyzeWith(
      "safe-command | denied-command",
      denyNamedCommand,
      fromInitialEnvironment({}, { workItems: 2, steps: 100 }),
    );
    const rejectedDeny = analyzeWith(
      "denied-command | safe-command",
      denyNamedCommand,
      fromInitialEnvironment({}, { workItems: 2, steps: 100 }),
    );
    const newlyAdmittedDeny = analyzeWith(
      "denied-command | safe-command",
      denyNamedCommand,
      fromInitialEnvironment({}, { workItems: 3, steps: 100 }),
    );

    expect(admittedDeny.completed.outcome).toMatchObject({ kind: "deny" });
    expect(rejectedDeny.completed.outcome).toMatchObject({ kind: "failure", budget: "max-work-items" });
    expect(newlyAdmittedDeny.completed.outcome).toMatchObject({ kind: "deny" });
    expect(analyzeWith(
      "safe-command | denied-command",
      denyNamedCommand,
      fromInitialEnvironment({}, { workItems: 2, steps: 1 }),
    ).completed.outcome).toMatchObject({ kind: "failure", budget: "max-work-items" });
  });

  test("property: internal admission ordering never replaces an admitted denial or duplicates callbacks", () => {
    for (let iteration = 0; iteration < 64; iteration++) {
      const denyOnRight = iteration % 2 === 0;
      const source = denyOnRight ? "safe-command | denied-command" : "denied-command | safe-command";
      const workItems = denyOnRight ? 2 : 3;
      const calls = new Map<string, number>();
      const result = analyzeWith(source, (request) => {
        const executable = request.command.executable?.kind === "known" ? request.command.executable.value : "unknown";
        calls.set(executable, (calls.get(executable) ?? 0) + 1);
        return denyNamedCommand(request);
      }, fromInitialEnvironment({}, { workItems, steps: 100 }));

      expect(result.completed.outcome, `${iteration}:${source}`).toMatchObject({ kind: "deny" });
      expect([...calls.values()].every((count) => count === 1), `${iteration}:${source}`).toBeTrue();
    }
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
        return script ? request.continueWithSource(script) : safe();
      });

      expect(result.completed.verdict, source).toMatchObject({ kind: "deny" });
      expect(result.depths.some((depth) => depth > 0)).toBeTrue();
    }
  });

  test("defaults callback continuation state to the normalized command-prefix environment", () => {
    const result = analyzeWith("TARGET=safe; TARGET=denied bash -c 'run \"$TARGET\"'", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "bash") {
        const script = knownArgument(request.command, 1);
        return script ? request.continueWithSource(script) : safe();
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
          return script ? request.continueWithSource(script, undefined, { isolate: false }) : safe();
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

  test("retains unresolved eval taint through an opaque structural child", () => {
    const environments: string[] = [];
    const result = analyzeWith('X=old; eval "$UNKNOWN"; run "$X"', (request) => {
      if (request.command.executable?.kind === "known") {
        environments.push(`${request.command.executable.value}:${lookupBinding(request.command.environment, "X").value.kind}`);
      }
      return dispatchCommand(request as never);
    });

    expect(environments).toEqual(["eval:known", "run:unknown"]);
    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("merges every non-isolated callback continuation environment", () => {
    const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "route") {
        const left = request.continueWithSource("X=left", undefined, { isolate: false });
        const right = request.continueWithSource("X=right", undefined, { isolate: false });
        return { outcome: safe(), children: [...childrenOf(left), ...childrenOf(right)] };
      }
      return safe();
    });

    expect(result.invocations.at(-1)?.argv).toEqual([unknownWord()]);
  });

  test("keeps explicit non-isolated replacement environments from producing a total safe result", () => {
    const result = analyzeWith("X=base; route; run \"$X\"", (request) => {
      if (request.command.executable?.kind === "known" && request.command.executable.value === "route") {
        const left = request.continueWithSource(":", fromInitialEnvironment({ X: "left" }), { isolate: false });
        const right = request.continueWithSource(":", fromInitialEnvironment({ X: "right" }), { isolate: false });
        return { outcome: safe(), children: [...childrenOf(left), ...childrenOf(right)] };
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
              children: order.flatMap((label) => childrenOf(
                request.continueWithSource(`X=${label}; branch ${label}`, undefined, { isolate: false }),
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
            children: permutation(labels, random).flatMap((label) => childrenOf(
              request.continueWithSource(`replacement-branch ${label}`, fromInitialEnvironment({ X: label }), { isolate: false }),
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

  test("property: nested calls never inherit omitted positional parameters", () => {
    const random = lcg(0x5511aa77);

    for (let iteration = 0; iteration < 64; iteration++) {
      const first = `caller-one-${random()}`;
      const second = `caller-two-${random()}`;
      const source = `outer(){ inner(){ run \"$1\" \"$2\"; }; inner; }; outer ${first} ${second}`;

      expect(argvs(analyze(source).invocations)).toEqual([["", ""]]);
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
  readonly continueWithSource: (source: string, environment?: ReturnType<typeof fromInitialEnvironment>, options?: { readonly isolate?: boolean }) => unknown;
  readonly continueWithInvocation: (
    words: readonly ResolvedWord[],
    environment?: ReturnType<typeof fromInitialEnvironment>,
    options?: { readonly processEffect?: "none" | "exec-replace" | "spawn-and-wait" | "spawn-async" | "spawn-repeated" | "unknown" },
  ) => unknown;
  readonly continueWithOpaque: (
    reason: "structural-parse-failure" | "source-parse-failure" | "source-file-execution" | "shell-startup-execution" | "unsupported-execution",
    environment?: ReturnType<typeof fromInitialEnvironment>,
    options?: { readonly processEffect?: "none" | "exec-replace" | "spawn-and-wait" | "spawn-async" | "spawn-repeated" | "unknown" },
  ) => unknown;
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
    preflightCommand,
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

function childrenOf(result: unknown): readonly unknown[] {
  if (!result || typeof result !== "object" || !("children" in result)) return [];
  const children = (result as { children?: unknown }).children;
  return Array.isArray(children) ? children : [];
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
