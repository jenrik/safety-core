import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-cst-"));

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

function programFor(source: string) {
  const result = parseBashProgram(source);
  expect(result.kind).not.toBe("parse-failure");
  if (result.kind === "parse-failure") throw new Error(result.reason);
  return result;
}

describe("parseBashProgram", () => {
  test("preserves ordered assignment prefixes, words, redirects, and source spans", () => {
    const source = "F=one D=two echo first second >output";
    const program = programFor(source);

    expect(program.statements[0]).toMatchObject({
      kind: "command",
      assignments: [
        { name: "F", value: { kind: "word", text: "one" } },
        { name: "D", value: { kind: "word", text: "two" } },
      ],
      words: [
        { kind: "word", text: "echo" },
        { kind: "word", text: "first" },
        { kind: "word", text: "second" },
      ],
      redirects: [{ kind: "output", target: { kind: "word", text: "output" } }],
    });
    expect(program.statements[0]?.span).toEqual({ start: 0, end: source.length });
  });

  test("projects functions, lists, subshells, brace groups, pipelines, and if statements", () => {
    expect(programFor("fn() { echo function; }").statements[0]).toMatchObject({
      kind: "function",
      name: "fn",
      body: { kind: "group" },
    });
    expect(programFor("echo left && echo right").statements[0]).toMatchObject({
      kind: "list",
      operators: ["&&"],
      statements: [{ kind: "command" }, { kind: "command" }],
    });
    const operators = Array.from({ length: 63 }, () => "&&" as const);
    const chain = Array.from({ length: 64 }, (_, index) => `command-${index}`)
      .map((command, index) => index === 0 ? command : `${operators[index - 1]} ${command}`)
      .join(" ");
    expect(programFor(chain).statements[0]).toMatchObject({
      kind: "list",
      operators,
      statements: Array.from({ length: 64 }, () => ({ kind: "command" })),
    });
    expect(programFor("command-0 && command-1 || command-2").statements[0]).toMatchObject({
      kind: "list",
      operators: ["||"],
      statements: [{ kind: "list", operators: ["&&"] }, { kind: "command" }],
    });
    expect(programFor("condition || # retained comment\ncommand").statements[0]).toMatchObject({
      kind: "list",
      operators: ["||"],
      statements: [{ kind: "command" }, { kind: "command" }],
    });
    expect(programFor("(echo sub)").statements[0]).toMatchObject({
      kind: "subshell",
      statements: [{ kind: "command" }],
    });
    expect(programFor("{ echo group; }").statements[0]).toMatchObject({
      kind: "group",
      statements: [{ kind: "command" }],
    });
    expect(programFor("echo a | sed s/a/b/").statements[0]).toMatchObject({
      kind: "pipeline",
      statements: [{ kind: "command" }, { kind: "command" }],
    });
    expect(programFor("if echo condition; then echo yes; else echo no; fi").statements[0]).toMatchObject({
      kind: "if",
      condition: [{ kind: "command" }],
      consequent: [{ kind: "command" }],
      alternate: [{ kind: "command" }],
    });
  });

  test("preserves unsupported syntax as a source-provenanced statement", () => {
    const source = "for item in one; do echo $item; done";
    const program = programFor(source);

    expect(program.statements).toEqual([
      expect.objectContaining({
        kind: "unsupported",
        reason: expect.stringContaining("for_statement"),
        span: { start: 0, end: source.length },
      }),
    ]);
  });

  test("returns a JSON-safe, deeply immutable projection", () => {
    const program = programFor("A=1 echo $(date) >out");
    const values: unknown[] = [program];
    while (values.length > 0) {
      const value = values.pop();
      if (value && typeof value === "object") {
        expect(Object.isFrozen(value)).toBeTrue();
        values.push(...Object.values(value));
      }
    }
    expect(JSON.parse(JSON.stringify(program))).toEqual(program);
  });

  test("retains reachable commands beneath unsupported control statements", () => {
    for (const [source, names] of [
      ["for item in one; do nested-for; done", ["nested-for"]],
      ["while true; do nested-while; done", ["true", "nested-while"]],
      ["case item in item) nested-case;; esac", ["nested-case"]],
    ] as const) {
      expect(JSON.stringify(programFor(source))).toContain(names.at(-1)!);
    }
  });

  test("projects command substitutions from assignments, redirects, and opaque words", () => {
    expect(programFor("value=$(nested-assignment) echo x").statements[0]).toMatchObject({
      kind: "command",
      assignments: [{ value: { kind: "command-substitution", statements: [{ kind: "command", words: [{ text: "nested-assignment" }] }] } }],
    });
    expect(programFor("echo x >$(nested-redirect)").statements[0]).toMatchObject({
      kind: "command",
      redirects: [{ target: { kind: "command-substitution", statements: [{ kind: "command", words: [{ text: "nested-redirect" }] }] } }],
    });
    expect(programFor("echo $(( $(nested-arithmetic) + 1))").statements[0]).toMatchObject({
      kind: "command",
      words: [{ text: "echo" }, { statements: [{ kind: "command", words: [{ text: "nested-arithmetic" }] }] }],
    });
  });

  test("retains nested command spans in lexical source order across locations", () => {
    const program = programFor("echo >$(nested-redirect) $(nested-argument)");
    const command = program.statements[0]!;
    expect(command).toMatchObject({
      kind: "command",
      words: [{ text: "echo" }],
      redirects: [{ words: [
        { kind: "command-substitution", statements: [{ kind: "command", words: [{ text: "nested-redirect" }] }] },
        { kind: "command-substitution", statements: [{ kind: "command", words: [{ text: "nested-argument" }] }] },
      ] }],
    });
    if (command.kind !== "command") throw new Error("expected command");
    expect(command.redirects[0]!.words[0]!.span.start).toBeLessThan(command.redirects[0]!.words[1]!.span.start);
  });

  test("projects descriptor-qualified redirects from destination fields only", () => {
    const source = "echo 2>$(nested-descriptor)";
    expect(programFor(source).statements[0]).toMatchObject({
      kind: "command",
      redirects: [{
        kind: "output",
        target: { kind: "command-substitution", text: "$(nested-descriptor)" },
        words: [{ kind: "command-substitution", text: "$(nested-descriptor)" }],
      }],
    });
  });

  test("retains redirected compound statement bodies and redirects", () => {
    const source = "{ nested-group; } >output";
    expect(programFor(source).statements[0]).toMatchObject({
      kind: "group",
      statements: [{ kind: "command", words: [{ text: "nested-group" }] }],
      redirects: [{ kind: "output", target: { text: "output" } }],
    });
  });

  test("discovers substitutions in redirects on supported compound statements", () => {
    expect(programFor("{ grouped; } >$(nested-compound-redirect)").statements[0]).toMatchObject({
      kind: "group",
      statements: [{ kind: "command", words: [{ text: "grouped" }] }],
      redirects: [{ target: { kind: "command-substitution", statements: [{ kind: "command", words: [{ text: "nested-compound-redirect" }] }] } }],
    });
  });

  test("projects a subshell function body instead of fabricating an empty group", () => {
    const source = "fn() (nested-function)";
    expect(programFor(source).statements[0]).toMatchObject({
      kind: "function",
      body: { kind: "subshell", statements: [{ kind: "command", words: [{ text: "nested-function" }] }] },
    });
  });

  test("property: generated syntax preserves spans, immutability, and nested discovery", () => {
    let state = 0x4d595df4;
    const next = (): number => {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      return state;
    };

    for (let index = 0; index < 128; index++) {
      const suffix = `${index}-${next() % 10000}`;
      const nested = `nested-${suffix}`;
      const source = [
        `value=$(nested-${suffix}) echo café-${suffix}`,
        `echo café-${suffix} >$(nested-${suffix})`,
        `echo $(( $(nested-${suffix}) + 1))`,
        `for item in one; do nested-${suffix}; done`,
        `while true; do nested-${suffix}; done`,
        `case item in item) nested-${suffix};; esac`,
        `{ nested-${suffix}; } >output-${suffix}`,
        `fn${index}() (nested-${suffix})`,
      ][next() % 8]!;
      const program = programFor(source);
      assertProjectionData(program, source);
      expect(JSON.stringify(program), source).toContain(nested);
    }
  });

  test("retains assignments in the program model", () => {
    expect(programFor("A=1 echo x").statements[0]).toMatchObject({
      kind: "command",
      assignments: [{ name: "A", value: { kind: "word", text: "1" } }],
    });
  });

  test("projects policy-relevant command substitutions without flattening", () => {
    expect(programFor("printf '%s' \"$(gh pr create --repo github.com/attacker/widgets --fill)\"").statements[0])
      .toMatchObject({
        kind: "command",
        words: [
          { text: "printf" },
          { text: "'%s'" },
          { parts: [{ kind: "command-substitution", statements: [{ kind: "command", words: [
            { text: "gh" }, { text: "pr" }, { text: "create" }, { text: "--repo" },
            { text: "github.com/attacker/widgets" }, { text: "--fill" },
          ] }] }] },
        ],
      });
  });
});

function assertProjectionData(value: unknown, source: string): void {
  if (!value || typeof value !== "object") return;
  expect(Object.isFrozen(value)).toBeTrue();
  const record = value as Record<string, unknown>;
  if ("span" in record) {
    const span = record.span as { start: number; end: number };
    expect(span.start).toBeGreaterThanOrEqual(0);
    expect(span.end).toBeGreaterThanOrEqual(span.start);
    expect(span.end).toBeLessThanOrEqual(source.length);
  }
  if (typeof record.text === "string" && "span" in record) {
    const span = record.span as { start: number; end: number };
    expect(source.slice(span.start, span.end)).toBe(record.text);
  }
  for (const child of Object.values(record)) assertProjectionData(child, source);
}
