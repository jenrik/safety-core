import { describe, expect, test } from "bun:test";

import { expandWord, type ResolvedWord } from "../src/bash/expand.ts";
import { fromInitialEnvironment } from "../src/bash/environment.ts";
import { scanOptions, type OptionGrammar } from "../src/bash/options.ts";

const GRAMMAR: OptionGrammar = Object.freeze({
  longResolution: "unique-prefix",
  options: Object.freeze([
    Object.freeze({ id: "flag", short: Object.freeze(["f"]), long: Object.freeze(["--flag"]), value: "none" }),
    Object.freeze({ id: "name", short: Object.freeze(["a"]), long: Object.freeze(["--name"]), value: "required", attached: true, equals: true }),
    Object.freeze({ id: "command", short: Object.freeze(["c"]), long: Object.freeze(["--command"]), value: "required", attached: true, equals: true, terminal: "immediate" }),
    Object.freeze({ id: "init-command", short: Object.freeze(["C"]), long: Object.freeze(["--init-command"]), value: "required", attached: true, equals: true }),
    Object.freeze({ id: "color", long: Object.freeze(["--color"]), value: "none" }),
  ]),
});

const DEFERRED_TERMINAL_GRAMMAR: OptionGrammar = Object.freeze({
  longResolution: "exact",
  options: Object.freeze([
    Object.freeze({ id: "command", short: Object.freeze(["c"]), value: "required", terminal: "deferred" }),
    Object.freeze({ id: "flag", short: Object.freeze(["e", "x"]), value: "none" }),
    Object.freeze({ id: "named-option", short: Object.freeze(["o", "O"]), value: "required", attached: true }),
  ]),
});

describe("declarative option scanner", () => {
  test.each([
    [["-f", "-a", "alias", "child"], ["flag", "name"], "child"],
    [["-faname", "child"], ["flag", "name"], "child"],
    [["--flag", "--name=alias", "child"], ["flag", "name"], "child"],
    [["--f", "--nam", "alias", "child"], ["flag", "name"], "child"],
    [["--", "-f"], [], "-f"],
  ] as const)("scans attached, separate, clustered, prefix, and -- forms: %o", (argv, ids, operand) => {
    const result = scanOptions(words(argv), GRAMMAR);
    expect(result.kind).toBe("parsed");
    if (result.kind !== "parsed") return;
    expect(result.options.map((option) => option.id)).toEqual(ids);
    expect(argv[result.operandIndex]).toBe(operand);
  });

  test("a value-taking short option consumes the cluster remainder", () => {
    const result = scanOptions(words(["-faname", "child"]), GRAMMAR);
    expect(result).toMatchObject({
      kind: "parsed",
      operandIndex: 1,
      options: [
        { id: "flag", attached: false },
        { id: "name", attached: true, value: { kind: "known", value: "name" } },
      ],
    });
  });

  test("terminal options stop with attached or separate values", () => {
    for (const argv of [["-cscript", "ignored"], ["-c", "script", "ignored"], ["--command=script", "ignored"]]) {
      const result = scanOptions(words(argv), GRAMMAR);
      expect(result).toMatchObject({ kind: "parsed", terminal: { id: "command", value: { kind: "known", value: "script" } } });
    }
  });

  test.each([
    [["-ce", "script", "arg"], ["command", "flag"], 2],
    [["-ec", "script", "arg"], ["flag", "command"], 2],
    [["-co", "pipefail", "script", "arg"], ["command", "named-option"], 3],
    [["-cO", "extglob", "script", "arg"], ["command", "named-option"], 3],
    [["-e", "-c", "script", "arg"], ["flag", "command"], 3],
    [["-o", "pipefail", "-cx", "script", "arg"], ["named-option", "command", "flag"], 4],
  ] as const)("defers a terminal source until the short cluster and its values are consumed: %o", (argv, ids, operandIndex) => {
    const result = scanOptions(words(argv), DEFERRED_TERMINAL_GRAMMAR);
    expect(result.kind).toBe("parsed");
    if (result.kind !== "parsed") return;
    expect(result.options.map((option) => option.id)).toEqual(ids);
    expect(result.terminal).toMatchObject({ id: "command", attached: false, value: { kind: "known", value: "script" } });
    expect(result.operandIndex).toBe(operandIndex);
  });

  test("rejects attached source for a deferred terminal option", () => {
    for (const argv of [["-cscript"], ["-cscript", "operand"]]) {
      expect(scanOptions(words(argv), DEFERRED_TERMINAL_GRAMMAR).kind).toBe("failure");
    }
  });

  test("property: valid pre-terminal option ordering preserves the deferred source boundary", () => {
    for (const ordered of permutations([["-e"], ["-o", "pipefail"]])) {
      const argv = [...ordered.flat(), "-cx", "script", "argument"];
      const result = scanOptions(words(argv), DEFERRED_TERMINAL_GRAMMAR);
      expect(result.kind, argv.join(" ")).toBe("parsed");
      if (result.kind === "parsed") {
        expect(result.terminal?.value).toEqual({ kind: "known", value: "script" });
        expect(argv.slice(result.operandIndex)).toEqual(["argument"]);
      }
    }
  });

  test("reports redacted typed failures for malformed and ambiguous forms", () => {
    expect(scanOptions(words(["--co"]), GRAMMAR)).toEqual({ kind: "failure", reason: "ambiguous-long-option" });
    expect(scanOptions(words(["--flag=value"]), GRAMMAR)).toEqual({ kind: "failure", reason: "unexpected-option-value" });
    expect(scanOptions(words(["-a"]), GRAMMAR)).toEqual({ kind: "failure", reason: "missing-option-value" });
    expect(scanOptions([{ kind: "unknown", reason: { kind: "generated" } }], GRAMMAR)).toEqual({ kind: "failure", reason: "dynamic-option" });
  });

  test("retains a recognized required option when its separate value is dynamic", () => {
    const dynamic: ResolvedWord = Object.freeze({ kind: "unknown", reason: Object.freeze({ kind: "generated" }) });
    const value = scanOptions([words(["-a"])[0]!, dynamic, words(["child"])[0]!], GRAMMAR);
    const terminal = scanOptions([words(["-c"])[0]!, dynamic], GRAMMAR);

    expect(value).toMatchObject({
      kind: "parsed",
      operandIndex: 2,
      options: [{ id: "name", value: { kind: "unknown" } }],
    });
    expect(terminal).toMatchObject({
      kind: "parsed",
      operandIndex: 2,
      terminal: { id: "command", value: { kind: "unknown" } },
    });
    expect(scanOptions(words(["-a"]), GRAMMAR)).toEqual({ kind: "failure", reason: "missing-option-value" });
  });

  test("property: dynamic required values preserve every recognized option identity", () => {
    const dynamic: ResolvedWord = Object.freeze({ kind: "unknown", reason: Object.freeze({ kind: "generated" }) });
    for (let index = 0; index < 64; index++) {
      const spelling = index % 2 === 0 ? "-a" : "--name";
      const result = scanOptions([words([spelling])[0]!, dynamic, words([`child-${index}`])[0]!], GRAMMAR);
      expect(result, spelling).toMatchObject({ kind: "parsed", options: [{ id: "name", value: { kind: "unknown" } }] });
    }
  });

  test("classifies symbolic attached, equals, and clustered option values", () => {
    for (const [source, id, terminal] of [
      ["-c$(opaque-command)", "command", true],
      ["--command=$(opaque-command)", "command", true],
      ["-fc$(opaque-command)", "command", true],
      ["-C$(opaque-command)", "init-command", false],
      ["--init-command=$(opaque-command)", "init-command", false],
    ] as const) {
      const result = scanOptions([symbolic(source)], GRAMMAR);
      expect(result.kind, source).toBe("parsed");
      if (result.kind === "parsed") {
        expect(result.options, source).toContainEqual(expect.objectContaining({ id, value: expect.objectContaining({ kind: "unknown" }) }));
        expect(result.terminal?.id === id, source).toBe(terminal);
      }
    }
  });

  test("keeps fully dynamic or ambiguously interrupted option identity unresolved", () => {
    for (const source of ["$(opaque-command)", "-$(opaque-command)c", "--comm$(opaque-command)=source"]) {
      expect(scanOptions([symbolic(source)], GRAMMAR), source).toEqual({ kind: "failure", reason: "dynamic-option" });
    }
  });

  test("property: static fish-style prefixes monotonically retain dynamic source identity", () => {
    for (let index = 0; index < 64; index++) {
      const prefix = index % 4 === 0 ? "-c" : index % 4 === 1 ? "-fc" : index % 4 === 2 ? "--command=" : "-C";
      const result = scanOptions([symbolic(`${prefix}$(opaque-${index})`)], GRAMMAR);
      expect(result.kind, prefix).toBe("parsed");
      if (result.kind === "parsed") {
        expect(result.options.some((option) => ["command", "init-command"].includes(option.id)), prefix).toBeTrue();
        expect(result.options.at(-1)?.value?.kind, prefix).toBe("unknown");
      }
    }
  });

  test("preserves exact named identities and rejects unsupported short-option polarity", () => {
    const grammar: OptionGrammar = Object.freeze({
      longResolution: "exact",
      shortPrefixes: Object.freeze(["-", "+"]),
      options: Object.freeze([
        Object.freeze({ id: "interactive", short: Object.freeze(["i"]), shortPrefixes: Object.freeze(["-"]), value: "none" }),
        Object.freeze({ id: "no-rcs", exact: Object.freeze(["+-RCS", "--no-rcs"]), value: "none" }),
      ]),
    });

    expect(scanOptions(words(["-i"]), grammar)).toMatchObject({ kind: "parsed", options: [{ id: "interactive", spelling: "-i" }] });
    expect(scanOptions(words(["+-RCS"]), grammar)).toMatchObject({ kind: "parsed", options: [{ id: "no-rcs", spelling: "+-RCS" }] });
    expect(scanOptions(words(["+i"]), grammar)).toEqual({ kind: "failure", reason: "unknown-option" });
  });

  test("property: option ordering preserves the operand boundary", () => {
    const forms = [["-f"], ["-aalias"], ["--name=alias"]];
    for (const ordered of permutations(forms)) {
      const argv = [...ordered.flat(), "child", "argument"];
      const result = scanOptions(words(argv), GRAMMAR);
      expect(result.kind, argv.join(" ")).toBe("parsed");
      if (result.kind === "parsed") expect(argv.slice(result.operandIndex)).toEqual(["child", "argument"]);
    }
  });
});

function words(values: readonly string[]): ResolvedWord[] {
  return values.map((value) => Object.freeze({ kind: "known", value }));
}

function symbolic(text: string): ResolvedWord {
  return expandWord({ kind: "word", text, span: { start: 0, end: text.length } }, fromInitialEnvironment());
}

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length <= 1) return [[...values]];
  return values.flatMap((value, index) => permutations([...values.slice(0, index), ...values.slice(index + 1)])
    .map((rest) => [value, ...rest]));
}
