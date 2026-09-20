import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { initBashParser, parseBashProgram } from "../src/index.ts";
import { expandWord, normalizeCommand, normalizedInvocation, symbolicWordShape, type ResolvedWord } from "../src/bash/expand.ts";
import {
  fromInitialEnvironment,
  known,
  lookupBinding,
  unknown,
  unset,
} from "../src/bash/environment.ts";
import type { BashCommand, BashConcatenationWord, BashWord } from "../src/bash/cst.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-expand-"));

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

describe("static Bash word expansion", () => {
  test("constructs argv children without reinterpreting shell syntax", () => {
    const environment = fromInitialEnvironment();
    const words = ["MODE=1", "a b", "", "$(not-source)"].map((value) => ({ kind: "known" as const, value }));

    const invocation = normalizedInvocation(words, environment);

    expect(invocation.executable).toEqual(words[0]);
    expect(invocation.argv).toEqual(words.slice(1));
    expect(invocation.environment).toBe(environment);
    expect(invocation.redirects).toEqual([]);
    expect([...invocation.assignmentPatch.writes]).toEqual([]);
  });

  test("property: normalized argv children preserve every generated word boundary", () => {
    for (let size = 1; size <= 32; size++) {
      const values = Array.from({ length: size }, (_unused, index) => `${index % 2 ? " " : "="}${index}`);
      const words = values.map((value) => ({ kind: "known" as const, value }));
      const invocation = normalizedInvocation(words, fromInitialEnvironment());

      expect([invocation.executable, ...invocation.argv].map((word) => word?.kind === "known" ? word.value : null)).toEqual(values);
    }
  });

  test("normalizes prefix assignments left-to-right for the child while words use the caller", () => {
    const normalized = normalizeCommand(command("F=BAR D=GAR echo $D $F"), fromInitialEnvironment());

    expect(normalized).toMatchObject({
      executable: { kind: "known", value: "echo" },
      argv: [
        { kind: "unknown", reason: { kind: "unknown-variable", variable: "D" } },
        { kind: "unknown", reason: { kind: "unknown-variable", variable: "F" } },
      ],
    });
    expect(lookupBinding(normalized.environment, "F").value).toEqual(known("BAR"));
    expect(lookupBinding(normalized.environment, "D").value).toEqual(known("GAR"));
  });

  test("does not expose prefix bindings to same-command literal concatenation", () => {
    const normalized = normalizeCommand(command("F=BAR echo prefix-$F-${F}"), fromInitialEnvironment());

    expect(normalized.argv).toMatchObject([{ kind: "unknown", reason: { variable: "F" } }]);
  });

  test("keeps single-quoted expansion markers literal", () => {
    const normalized = normalizeCommand(command("F=BAR echo '\\$F'"), fromInitialEnvironment());

    expect(normalized.argv).toEqual([{ kind: "known", value: "\\$F" }]);
  });

  test("keeps non-empty double-quoted literal arguments statically known", () => {
    const normalized = normalizeCommand(command('bash -c "cat credentials.json"'), fromInitialEnvironment());

    expect(normalized.argv).toEqual([
      { kind: "known", value: "-c" },
      { kind: "known", value: "cat credentials.json" },
    ]);
  });

  test("keeps the literal find placeholder distinct from brace expansion", () => {
    const normalized = normalizeCommand(command("find . -exec cat {} ;"), fromInitialEnvironment());

    expect(normalized.argv).toContainEqual({ kind: "known", value: "{}" });
  });

  test("marks an unknown direct dependency without exposing a value", () => {
    const source = "$COMMAND";
    const unresolved = expandWord(word(source), fromInitialEnvironment({ COMMAND: unknown({ kind: "ambient" }) }));

    expect(unresolved).toMatchObject({
      kind: "unknown",
      reason: {
        kind: "unknown-variable",
        variable: "COMMAND",
        span: { start: 5, end: 5 + source.length },
      },
    });
    expect(unresolved).not.toHaveProperty("value");
  });

  test("keeps the immediate variable and source provenance when an unknown assignment is referenced", () => {
    const source = "F=$COMMAND echo $F";
    const commandNode = command(source);
    const referenced = commandNode.words[1]!;
    const normalized = normalizeCommand(commandNode, fromInitialEnvironment({ COMMAND: unknown({ kind: "ambient" }) }));

    expect(normalized.argv).toEqual([{
      kind: "unknown",
      reason: {
        kind: "unknown-variable",
        variable: "F",
        span: referenced.span,
      },
    }]);
    expect(normalized.argv[0]).not.toHaveProperty("value");
  });

  test("marks dynamic and unsupported forms unknown with redacted source provenance", () => {
    for (const [source, variable] of [
      ["$(id)", undefined],
      ["<(id)", undefined],
      ["${!F}", "F"],
      ["$((1 + 1))", undefined],
      ["${F:-fallback}", "F"],
      ["${F[@]}", "F"],
      ["*.json", undefined],
    ] as const) {
      const input = word(source);
      const result = expandWord(input, fromInitialEnvironment({ F: "value" }));

      expect(result).toMatchObject({ kind: "unknown", reason: { span: input.span } });
      if (variable) expect(result).toMatchObject({ reason: { variable } });
      expect(result).not.toHaveProperty("value");
    }
  });

  test("retains symbolic fragments and field cardinality outside serialized words", () => {
    const quoted = expandWord(word('"prefix-$(opaque-command)-suffix"'), fromInitialEnvironment());
    const unquoted = expandWord(word("prefix-$(opaque-command)-suffix"), fromInitialEnvironment());
    const pure = expandWord(word("$(opaque-command)"), fromInitialEnvironment());

    expect(symbolicWordShape(quoted)).toEqual({
      fragments: [
        { kind: "literal", value: "prefix-" },
        { kind: "unknown" },
        { kind: "literal", value: "-suffix" },
      ],
      fields: "one",
    });
    expect(symbolicWordShape(unquoted)).toMatchObject({ fields: "one-or-more" });
    expect(symbolicWordShape(pure)).toEqual({ fragments: [{ kind: "unknown" }], fields: "zero-or-more" });
    expect(JSON.stringify(quoted)).not.toContain("prefix-");
    expect(JSON.stringify(unquoted)).not.toContain("suffix");
  });

  test("property: quoting changes symbolic cardinality without exposing literal canaries", () => {
    for (let index = 0; index < 64; index++) {
      const canary = `symbolic-canary-${index}`;
      for (const [source, fields] of [
        [`"${canary}$(opaque-command)"`, "one"],
        [`${canary}$(opaque-command)`, "one-or-more"],
      ] as const) {
        const resolved = expandWord(word(source), fromInitialEnvironment());
        expect(symbolicWordShape(resolved)?.fields, source).toBe(fields);
        expect(JSON.stringify(resolved), source).not.toContain(canary);
      }
    }
  });

  test("keeps only shape-stable unquoted expansion known in executable, argv, and redirects", () => {
    const split = fromInitialEnvironment({ VALUE: "two words" });
    const empty = fromInitialEnvironment({ VALUE: "" });
    const glob = fromInitialEnvironment({ VALUE: "*.ts" });

    expect(normalizeCommand(command("$VALUE"), split).executable).toMatchObject({ kind: "unknown" });
    expect(normalizeCommand(command("echo $VALUE"), empty).argv[0]).toMatchObject({ kind: "unknown" });
    expect(normalizeCommand(command("echo $VALUE"), glob).argv[0]).toMatchObject({ kind: "unknown" });
    expect(normalizeCommand(command("echo ok >$VALUE"), split).redirects[0]?.target).toMatchObject({ kind: "unknown" });
    expect(normalizeCommand(command("echo \"$VALUE\""), split).argv).toEqual([{ kind: "known", value: "two words" }]);
  });

  test("keeps assignment RHS expansion known despite unquoted field and pathname characters", () => {
    const normalized = normalizeCommand(command("TARGET=$VALUE echo ok"), fromInitialEnvironment({ VALUE: "two words" }));

    expect(lookupBinding(normalized.environment, "TARGET").value).toEqual(known("two words"));
  });

  test("uses default, known custom, and unknown IFS for unquoted field cardinality", () => {
    const defaultIfs = fromInitialEnvironment({ VALUE: "stable" });
    const customIfs = fromInitialEnvironment({ IFS: ":", VALUE: "left:right" });
    const disabledIfs = fromInitialEnvironment({ IFS: "", VALUE: "left:right" });
    const unknownIfs = fromInitialEnvironment({ IFS: unknown({ kind: "ambient" }), VALUE: "stable" });

    expect(normalizeCommand(command("echo $VALUE"), defaultIfs).argv).toEqual([{ kind: "known", value: "stable" }]);
    expect(normalizeCommand(command("echo $VALUE"), customIfs).argv[0]).toMatchObject({ kind: "unknown" });
    expect(normalizeCommand(command("echo $VALUE"), disabledIfs).argv).toEqual([{ kind: "known", value: "left:right" }]);
    expect(normalizeCommand(command("echo $VALUE"), unknownIfs).argv[0]).toMatchObject({ kind: "unknown" });
  });

  test("marks every non-name dollar, tilde, and brace expansion form unknown", () => {
    for (const source of ["$?", "$$", "$#", "$@", "$*", "$1", "$[1+1]", "~", "{left,right}"]) {
      const result = expandWord(rawWord(source), fromInitialEnvironment());

      expect(result).toMatchObject({ kind: "unknown", reason: { span: { start: 0, end: source.length } } });
      expect(result).not.toHaveProperty("value");
    }
  });

  test("honors unsupported CST children embedded in concatenations", () => {
    const input: BashConcatenationWord = {
      kind: "concatenation",
      text: "safe-opaque",
      parts: [{
        kind: "concatenation",
        text: "opaque",
        parts: [{
          kind: "unsupported-word",
          text: "opaque",
          reason: "adapter-specific",
          statements: [],
          span: { start: 5, end: 11 },
        }],
        span: { start: 5, end: 11 },
      }],
      span: { start: 0, end: 11 },
    };

    expect(expandWord(input, fromInitialEnvironment())).toMatchObject({
      kind: "unknown",
      reason: { kind: "unsupported-word", span: (input.parts[0]! as BashConcatenationWord).parts[0]!.span },
    });
  });

  test("removes unquoted and double-quoted backslash-newline continuations", () => {
    expect(expandWord(rawWord("before\\\nafter"), fromInitialEnvironment())).toEqual({ kind: "known", value: "beforeafter" });
    expect(expandWord(rawWord('"before\\\nafter"'), fromInitialEnvironment())).toEqual({ kind: "known", value: "beforeafter" });
  });

  test("does not claim an exact result for backslash-CRLF", () => {
    for (const input of [rawWord("before\\\r\nafter"), rawWord('"before\\\r\nafter"')]) {
      expect(expandWord(input, fromInitialEnvironment())).toMatchObject({ kind: "unknown", reason: { span: input.span } });
    }
  });

  test("expands redirect targets against the caller environment", () => {
    const normalized = normalizeCommand(command("OUT=result echo ok >$OUT"), fromInitialEnvironment());

    expect(normalized.redirects).toMatchObject([{
      kind: "output",
      target: { kind: "unknown", reason: { variable: "OUT" } },
    }]);
  });

  test("keeps prefix assignments in the normalized command overlay only", () => {
    const initial = fromInitialEnvironment({ F: "caller" });
    const normalized = normalizeCommand(command("F=prefix echo $F"), initial);

    expect(lookupBinding(initial, "F").value).toEqual(known("caller"));
    expect(normalized.environment.frame).toBe(initial.frame);
    expect(normalized.environment.overlay).toBeDefined();
    expect(lookupBinding(normalized.environment, "F").value).toEqual(known("prefix"));
    expect([...normalized.assignmentPatch.writes]).toEqual(["F"]);
  });

  test("returns a persistent patch for a standalone assignment command", () => {
    const initial = fromInitialEnvironment();
    const normalized = normalizeCommand(command("F=BAR"), initial);

    expect(normalized.executable).toBeNull();
    expect(lookupBinding(initial, "F").value).toEqual(unset());
    expect(lookupBinding(normalized.assignmentPatch.environment, "F").value).toEqual(known("BAR"));
    expect([...normalized.assignmentPatch.writes]).toEqual(["F"]);
  });

  test("returns deeply frozen normalized snapshots without mutable write-set state", () => {
    const normalized = normalizeCommand(
      command("F=prefix echo $MISSING >$F"),
      fromInitialEnvironment({ MISSING: unknown({ kind: "ambient" }) }),
    );
    const unknownArgument = normalized.argv[0]!;
    const redirect = normalized.redirects[0]!;

    expect(Object.isFrozen(normalized)).toBeTrue();
    expect(Object.isFrozen(normalized.argv)).toBeTrue();
    expect(Object.isFrozen(normalized.redirects)).toBeTrue();
    expect(Object.isFrozen(normalized.assignmentPatch)).toBeTrue();
    expect(Object.isFrozen(normalized.assignmentPatch.writes)).toBeTrue();
    expect(Object.isFrozen(unknownArgument)).toBeTrue();
    expect(Object.isFrozen((unknownArgument as { reason: object }).reason)).toBeTrue();
    expect(Object.isFrozen((unknownArgument as { reason: { span: object } }).reason.span)).toBeTrue();
    expect(Object.isFrozen(redirect)).toBeTrue();
    expect(() => { (normalized as { executable: unknown }).executable = null; }).toThrow();
    expect(() => { (normalized.argv as ResolvedWord[]).push({ kind: "known", value: "changed" }); }).toThrow();
    expect(() => { (normalized.redirects as typeof normalized.redirects extends readonly (infer T)[] ? T[] : never).push(redirect); }).toThrow();
    expect(() => { ((unknownArgument as { reason: { span: { start: number } } }).reason.span).start = 99; }).toThrow();
    expect(() => { (normalized.assignmentPatch.writes as Set<string>).add("CHANGED"); }).toThrow();
    expect(normalized.argv[0]).toMatchObject({ kind: "unknown", reason: { variable: "MISSING" } });
    expect(redirect.target).toMatchObject({ kind: "unknown", reason: { variable: "F" } });
    expect(normalized.redirects).toEqual([redirect]);
    expect([...normalized.assignmentPatch.writes]).toEqual(["F"]);
  });

  test("property: generated known assignment chains match a left-to-right model", () => {
    const random = lcg(0x3c6ef372);

    for (let iteration = 0; iteration < 128; iteration++) {
      const count = 2 + (random() % 7);
      const expected = new Map<string, string>();
      const assignments: string[] = [];
      const observed: string[] = [];

      for (let index = 0; index < count; index++) {
        const name = `V${iteration}_${index}`;
        if (index === 0 || random() % 2 === 0) {
          const value = `literal-${iteration}-${random()}`;
          assignments.push(`${name}=${value}`);
          expected.set(name, value);
        } else {
          const dependency = `V${iteration}_${random() % index}`;
          assignments.push(`${name}=$${dependency}`);
          expected.set(name, expected.get(dependency)!);
        }
        observed.push(name);
      }

      const normalized = normalizeCommand(command(`${assignments.join(" ")} echo ${observed.map((name) => `$${name}`).join(" ")}`), fromInitialEnvironment());
      expect(normalized.argv).toHaveLength(observed.length);
      expect(normalized.argv.every((word) => word.kind === "unknown")).toBeTrue();
      expect(observed.map((name) => lookupBinding(normalized.environment, name).value))
        .toEqual(observed.map((name) => known(expected.get(name)!)));
    }
  });

  test("property: unknown dependency chains stay unknown until a literal overwrite", () => {
    const random = lcg(0x9e3779b9);

    for (let iteration = 0; iteration < 128; iteration++) {
      const first = `FIRST_${iteration}`;
      const second = `SECOND_${iteration}`;
      const restored = `restored-${random()}`;
      const normalized = normalizeCommand(
        command(`${first}=$MISSING ${second}=$${first} ${first}=${restored} echo $${second} $${first}`),
        fromInitialEnvironment({ MISSING: unknown({ kind: "ambient" }) }),
      );

      expect(normalized.argv[0]).toMatchObject({
        kind: "unknown",
        reason: { kind: "unknown-variable", variable: second },
      });
      expect(normalized.argv[0]).not.toHaveProperty("value");
      expect(normalized.argv[1]).toMatchObject({ kind: "unknown", reason: { variable: first } });
      expect(lookupBinding(normalized.environment, first).value).toEqual(known(restored));
      expect(lookupBinding(normalized.environment, second).value).toMatchObject({ kind: "unknown" });
    }
  });
});

function command(source: string): BashCommand {
  const program = parseBashProgram(source);
  expect(program.kind).toBe("program");
  if (program.kind !== "program") throw new Error(program.reason);
  const statement = program.statements[0];
  expect(statement?.kind).toBe("command");
  if (!statement || statement.kind !== "command") throw new Error("Expected one command");
  return statement;
}

function word(source: string): BashWord {
  const commandNode = command(`echo ${source}`);
  const input = commandNode.words[1];
  if (!input) throw new Error("Expected one word");
  return input;
}

function rawWord(text: string): BashWord {
  return { kind: "word", text, span: { start: 0, end: text.length } };
}

function lcg(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}
