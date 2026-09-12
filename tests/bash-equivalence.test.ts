import { afterAll, beforeAll, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeBashAuthorization, initBashParser } from "../src/index.ts";
import type { CommandHandler, InvocationCursor } from "../src/bash/dispatch.ts";
import { lookupBinding } from "../src/bash/environment.ts";
import { safe } from "../src/bash/outcome.ts";
import { runBashOracle } from "./helpers/bash-oracle.ts";

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

  expect(trace).toEqual([{
    argv: ["", ""],
    environment: { BASE: "root", D: "GAR", F: "BAR" },
  }]);
});

test("matches real Bash by expanding same-command words before prefix assignments", async () => {
  const source = 'F=BAR D=GAR record-command "$D" "$F"';
  await expectEquivalent(source, { BASE: "root" });
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
  await expectEquivalent(source, { BASE: "root" });
});

test("matches generated supported programs from a deterministic grammar", async () => {
  const random = lcg(0x5afe_c0de);

  for (let index = 0; index < 32; index++) {
    await expectEquivalent(generatedProgram(random, index), { BASE: "root" });
  }
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

async function expectEquivalent(source: string, environment: Readonly<Record<string, string>>) {
  const oracle = await runBashOracle(source, environment);
  const invocations: InvocationCursor[] = [];
  const result = analyzeBashAuthorization({
    source,
    initialEnvironment: { kind: "verified", values: environment },
    includeBaseHandlers: false,
    handlers: [recordingHandler(invocations)],
  });

  expect(result.verdict.kind).not.toEqual("deny");
  expect(renderInvocations(invocations, ["BASE", "D", "EXPORTED", "F", "X"])).toEqual(oracle);
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

function generatedProgram(random: () => number, index: number): string {
  const first = `one_${index}_${random()}`;
  const second = `two_${index}_${random()}`;
  const child = `child_${index}_${random()}`;
  return [
    `X=${first}`,
    'record-command "$X"',
    `{ X=${second}; }`,
    'record-command "$X"',
    `( X=${child}; record-command "$X" )`,
    'record-command "$X"',
  ].join("; ");
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
