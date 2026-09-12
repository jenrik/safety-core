import { afterAll, beforeAll, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeBashAuthorization, initBashParser } from "../src/index.ts";
import type { CommandHandler, InvocationCursor } from "../src/bash/dispatch.ts";
import { lookupBinding } from "../src/bash/environment.ts";
import { safe } from "../src/bash/outcome.ts";
import {
  assertEquivalentOracleFinalBindings,
  assertEquivalentOracleTrace,
  runBashOracle,
  runBashOracleWithFinalBindings,
} from "./helpers/bash-oracle.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-equivalence-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

test("records a command-local assignment overlay under an empty Bash environment", async () => {
  const trace = await runBashOracle('F=BAR D=GAR record-command "$D" "$F"', { BASE: "root" });

  assertEquivalentOracleTrace(trace, [{
    argv: ["", ""],
    environment: { BASE: "root", D: "GAR", F: "BAR" },
  }]);
});

test("reserves oracle PATH and trace controls after caller test environment", async () => {
  const trace = await runBashOracle('record-command stable', {
    BASH_ORACLE_TRACE: "caller-controlled",
    PATH: "caller-controlled",
  });

  assertEquivalentOracleTrace(trace, [{ argv: ["stable"], environment: {} }]);
});

test("reserves BASH_ENV so noninteractive Bash cannot inject a fixture command", async () => {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-bash-startup-"));
  const startup = join(directory, "startup.bash");
  writeFileSync(startup, "record-command injected\n");
  try {
    const trace = await runBashOracle("record-command requested", { BASH_ENV: startup });

    assertEquivalentOracleTrace(trace, [{ argv: ["requested"], environment: {} }]);
  } finally {
    rmSync(directory, { force: true, recursive: true });
  }
});

test("captures a redacted final shell-binding snapshot without values", async () => {
  const oracle = await runBashOracleWithFinalBindings(
    "X=one; export Y=two; unset Z",
    { BASE: "root" },
    ["BASE", "X", "Y", "Z"],
  );

  assertEquivalentOracleFinalBindings(oracle.finalBindings, {
    BASE: { kind: "set", exported: true },
    X: { kind: "set", exported: false },
    Y: { kind: "set", exported: true },
    Z: { kind: "unset", exported: false },
  });
  expect(JSON.stringify(oracle.finalBindings)).not.toContain("one");
  expect(JSON.stringify(oracle.finalBindings)).not.toContain("two");
});

test("redacts recorded values from equivalence mismatch diagnostics", () => {
  const marker = "must-not-appear-in-diagnostics";
  let message = "";
  try {
    assertEquivalentOracleTrace(
      [{ argv: [marker], environment: { SAMPLE: marker } }],
      [{ argv: [], environment: {} }],
    );
  } catch (error) {
    message = error instanceof Error ? error.message : "";
  }

  expect(message).toContain("Redacted Bash oracle trace mismatch");
  expect(message).not.toContain(marker);
});

test("matches real Bash by expanding same-command words before prefix assignments", async () => {
  const source = 'F=BAR D=GAR record-command "$D" "$F"';
  await expectEquivalent(source, { BASE: "root" }, ["BASE", "D", "F"]);
});

test.each([
  ["persists standalone assignments", 'X=one; record-command "$X"; X=two; record-command "$X"'],
  ["uses dynamically scoped function bindings", 'X=outer; f(){ record-command "$X"; }; X=inner f; record-command "$X"'],
  ["keeps local bindings inside a function", 'X=outer; f(){ local X=inner; record-command "$X"; }; f; record-command "$X"'],
  ["models export and unset", 'export X=one; record-command "$X"; unset X; record-command "$X"'],
  ["retains brace group writes", 'X=outer; { X=group; }; record-command "$X"'],
  ["isolates subshell writes", 'X=outer; ( X=child; record-command "$X"; ); record-command "$X"'],
  ["merges conditionals with identical writes", 'X=before; if :; then X=joined; else X=joined; fi; record-command "$X"'],
  ["walks a transparent command wrapper", 'X=wrapped; command record-command "$X"'],
])("matches real Bash when it %s", async (_name, source) => {
  await expectEquivalent(source, { BASE: "root" }, ["BASE", "X"]);
});

test("matches generated supported programs from a deterministic grammar", async () => {
  const random = lcg(0x5afe_c0de);
  const variants = new Set<string>();

  for (let index = 0; index < 48; index++) {
    const generated = generatedProgram(random, index);
    variants.add(generated.variant);
    await expectEquivalent(generated.source, { BASE: "root" }, ["BASE", "X"]);
  }
  expect(variants).toEqual(new Set(["assignment-group", "dynamic-function", "export-unset", "subshell", "conditional", "wrapper"]));
});

test("keeps unsupported mutation neutral and taints subsequent expansion", () => {
  const invocations: InvocationCursor[] = [];
  const result = analyzeBashAuthorization({
    source: 'X=known; eval "$PAYLOAD"; record-command "$X"',
    initialEnvironment: { kind: "verified", values: { BASE: "root" } },
    includeBaseHandlers: false,
    handlers: [recordingHandler(invocations)],
  });

  expect(result.verdict).toEqual({ kind: "neutral" });
  expect(invocations).toHaveLength(1);
  expect(invocations[0]?.invocation.argv).toEqual([expect.objectContaining({ kind: "unknown" })]);
});

function recordingHandler(invocations: InvocationCursor[]): CommandHandler {
  return Object.freeze({
    name: "record-command",
    handle(cursor) {
      invocations.push(cursor);
      return safe();
    },
  });
}

async function expectEquivalent(
  source: string,
  environment: Readonly<Record<string, string>>,
  finalBindingNames: readonly string[] = [],
) {
  const oracle = finalBindingNames.length > 0
    ? await runBashOracleWithFinalBindings(source, environment, finalBindingNames)
    : { trace: await runBashOracle(source, environment), finalBindings: undefined };
  const invocations: InvocationCursor[] = [];
  let finalBindings: ReturnType<typeof renderFinalBindings> | undefined;
  const result = analyzeBashAuthorization({
    source: finalBindingNames.length > 0 ? `${source}\ncapture-final` : source,
    initialEnvironment: { kind: "verified", values: environment },
    includeBaseHandlers: false,
    handlers: [recordingHandler(invocations), finalBindingHandler(finalBindingNames, (snapshot) => { finalBindings = snapshot; })],
  });

  expect(result.verdict.kind).not.toEqual("deny");
  assertEquivalentOracleTrace(renderInvocations(invocations, ["BASE", "D", "EXPORTED", "F", "X"]), oracle.trace);
  if (oracle.finalBindings) {
    expect(finalBindings).toBeDefined();
    assertEquivalentOracleFinalBindings(finalBindings!, oracle.finalBindings);
  }
}

function finalBindingHandler(
  names: readonly string[],
  capture: (snapshot: ReturnType<typeof renderFinalBindings>) => void,
): CommandHandler {
  return Object.freeze({
    name: "capture-final",
    handle(cursor) {
      capture(renderFinalBindings(cursor, names));
      return safe();
    },
  });
}

function renderInvocations(invocations: readonly InvocationCursor[], names: readonly string[]) {
  return invocations.map((cursor) => ({
    argv: cursor.invocation.argv.map((word) => word.kind === "known" ? word.value : "<unknown>"),
    environment: Object.fromEntries(names.flatMap((name) => {
      const binding = lookupBinding(cursor.invocation.environment, name);
      return binding.exported && binding.value.kind === "known" ? [[name, binding.value.value]] : [];
    })),
  }));
}

function renderFinalBindings(cursor: InvocationCursor, names: readonly string[]) {
  return Object.fromEntries(names.map((name) => {
    const binding = lookupBinding(cursor.invocation.environment, name);
    return [name, binding.value.kind === "unset"
      ? { kind: "unset", exported: false }
      : { kind: binding.value.kind === "known" ? "set" : "unknown", exported: binding.exported }];
  }));
}

function generatedProgram(random: () => number, index: number): { readonly variant: string; readonly source: string } {
  const first = `one_${index}_${random()}`;
  const second = `two_${index}_${random()}`;
  const child = `child_${index}_${random()}`;
  const variants = [
    ["assignment-group", [`X=${first}`, 'record-command "$X"', `{ X=${second}; }`, 'record-command "$X"']],
    ["dynamic-function", [`X=${first}`, `f(){ record-command "$X"; }`, `X=${second} f`, 'record-command "$X"']],
    ["export-unset", [`export X=${first}`, 'record-command "$X"', "unset X", 'record-command "$X"']],
    ["subshell", [`X=${first}`, `( X=${child}; record-command "$X" )`, 'record-command "$X"']],
    ["conditional", [`X=${first}`, `if :; then X=${second}; else X=${second}; fi`, 'record-command "$X"']],
    ["wrapper", [`X=${first}`, 'command record-command "$X"']],
  ] as const;
  const [variant, statements] = variants[index % variants.length]!;
  return { variant, source: statements.join("; ") };
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
