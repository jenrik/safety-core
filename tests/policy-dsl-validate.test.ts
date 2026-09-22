import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import { POLICY_LANGUAGE_V1, parsePolicyDocument, validatePolicyDocument } from "../src/policy/dsl/validate.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { BUILTINS_V1 } from "../src/policy/dsl/builtins.ts";

const policy = (): Record<string, unknown> => ({
  language: POLICY_LANGUAGE_V1,
  layer: "permission",
  select: [{ kind: "invocation" }],
  registers: {
    seen: { type: "bool", initial: false },
    mode: { type: "enum", values: ["read", "write"], initial: "read" },
    count: { type: "count", max: 3, initial: 0 },
    value: { type: "inputRef", initial: null },
  },
  options: {
    namespace: {
      names: ["-n", "--namespace"],
      value: "required",
      forms: ["separate", "attachedShort", "equalsLong", "cluster"],
      availableIn: "*",
      set: { value: { ref: "option.value" } },
    },
  },
  start: "command",
  states: {
    command: {
      cases: [{ when: { call: "equals", args: [{ ref: "word" }, "get"] }, action: { consume: "word", next: "tail", set: { seen: true } } }],
      default: { decision: "ignore" },
      end: { decision: "ignore" },
    },
    tail: {
      cases: [{ when: true, action: { consume: "word", next: "tail", set: { count: 1 } } }],
      default: { decision: "defer" },
      end: { decision: "allow", reason: ["approved ", { ref: "value" }], audit: { namespace: { ref: "value" } } },
    },
  },
});

function invalid(mutator: (document: Record<string, any>) => void): void {
  const document = policy();
  mutator(document);
  expect(() => validatePolicyDocument(document)).toThrow();
}

describe("DCRM JSON policy validation", () => {
  test("parses the exact v1 document and compiles ordered options", () => {
    const ast = parsePolicyDocument(JSON.stringify(policy()));
    const compiled = compilePolicyDocument(ast);

    expect(compiled.language).toBe(POLICY_LANGUAGE_V1);
    expect(compiled.states.command.cases[0]?.origin).toBe("option:namespace");
    expect(compiled.states.command.cases[1]?.origin).toBe("state:command");
    expect(compiled.states.tail.cases[0]?.origin).toBe("option:namespace");
    expect(compiled.options.namespace).toEqual({
      names: ["-n", "--namespace"],
      value: "required",
      forms: ["separate", "attachedShort", "equalsLong", "cluster"],
      availableIn: "*",
      set: { value: { ref: "option.value" } },
    });
    expect(compiled.states.command.cases[0]?.action).toMatchObject({
      kind: "option",
      forms: ["separate", "attachedShort", "equalsLong", "cluster"],
      value: "required",
      minProgress: 1,
      clusterByteProgress: true,
    });
    expect(Object.values(compiled.states).every((state) => state.default.kind === "terminal" && state.end.kind === "terminal")).toBeTrue();
    expect(compiled.metrics.transitions).toBeGreaterThan(0);
  });

  test("lowers machine-wide and state-local options in declaration order", () => {
    const document = policy();
    document.options.tailFlag = { names: ["--tail"], value: "absent", forms: [], availableIn: ["tail"] };
    const compiled = compilePolicyDocument(validatePolicyDocument(document));

    expect(compiled.states.command.cases.map((entry) => entry.origin)).toEqual(["option:namespace", "state:command"]);
    expect(compiled.states.tail.cases.map((entry) => entry.origin)).toEqual(["option:namespace", "option:tailFlag", "state:tail"]);
    expect(compiled.options.tailFlag).toMatchObject({ names: ["--tail"], availableIn: ["tail"] });
  });

  test("rejects exact-version and unknown-key violations", () => {
    invalid((document) => { document.language = "safety-core/bash-policy-v2"; });
    invalid((document) => { document.unrecognized = true; });
    invalid((document) => { document.states.command.unrecognized = true; });
    invalid((document) => { document.states.command.cases[0].action.unrecognized = true; });
    expect(() => parsePolicyDocument('{"language":"safety-core/bash-policy-v1","language":"safety-core/bash-policy-v1"}')).toThrow("duplicate JSON object key");
  });

  test("requires resolved unique names and terminal default/end behavior", () => {
    invalid((document) => { document.start = "missing"; });
    invalid((document) => { document.states.command.cases[0].action.next = "missing"; });
    invalid((document) => { document.states.command.default = { consume: "word", next: "command" }; });
    invalid((document) => { document.states.command.end = { consume: "word", next: "command" }; });
    invalid((document) => { document.registers = { "bad-name!": { type: "bool", initial: false } }; });
  });

  test("enforces action and expression typing and guard capabilities", () => {
    invalid((document) => { document.states.command.cases[0].when = "not-a-boolean"; });
    invalid((document) => { document.states.command.cases[0].action.set = { seen: "not-a-bool" }; });
    invalid((document) => { document.states.command.cases[0].action.set = { unknown: true }; });
    invalid((document) => { document.states.command.cases[0].when = { call: "doesNotExist", args: [] }; });
    invalid((document) => { document.layer = "guard"; document.states.tail.end.decision = "allow"; });
    invalid((document) => {
      document.registers.otherMode = { type: "enum", values: ["other"], initial: "other" };
      document.states.command.cases[0].action.set = { mode: { ref: "otherMode" } };
    });
    invalid((document) => { document.states.command.cases[0].action.set = { mode: { call: "asciiLower", args: ["READ"] } }; });
    invalid((document) => {
      document.registers.larger = { type: "count", max: 4, initial: 0 };
      document.states.command.cases[0].action.set = { count: { ref: "larger" } };
    });
    invalid((document) => { document.states.command.cases[0].action.set = { count: { call: "parseBoundedInt", args: [{ ref: "word" }, 4] } }; });
    expect(() => validatePolicyDocument(withAssignment({ count: { call: "parseBoundedInt", args: [{ ref: "word" }, 3] } }))).not.toThrow();
  });

  test("proves every compiled nonterminal transition consumes forward progress", () => {
    invalid((document) => { document.states.command.cases[0].action.consume = 0; });
    invalid((document) => { document.states.command.cases[0].action.consume = "clusterByte"; });
    invalid((document) => { document.options.namespace.forms = ["separate"]; document.options.namespace.value = "absent"; });
    invalid((document) => { document.options.namespace.forms = []; document.options.namespace.value = "absent"; });

    const compiled = compilePolicyDocument(validatePolicyDocument(policy()));
    for (const state of Object.values(compiled.states)) {
      for (const entry of state.cases) {
        if (entry.action.kind === "transition") expect(entry.action.progress).toBeGreaterThan(0);
      }
    }
  });

  test("rejects cyclic fragments, nested/dynamic folds, and source size excess", () => {
    invalid((document) => {
      document.fragments = {
        first: { uses: ["second"], cases: [] },
        second: { uses: ["first"], cases: [] },
      };
      document.states.command.fragments = ["first"];
    });
    invalid((document) => { document.folds = { redirects: { collection: "redirects", operation: "any", when: { ref: "fold.item" }, fold: "other" } }; });
    invalid((document) => { document.folds = { redirects: { collection: "register.values", operation: "any", when: true } }; });
    invalid((document) => {
      document.fragments = { invalid: { cases: [{ when: true, action: { consume: "word", next: "absent" } }] } };
      document.states.command.fragments = ["invalid"];
    });
    invalid((document) => { document.states = Object.fromEntries(Array.from({ length: 129 }, (_, index) => [`s${index}`, { cases: [], default: { decision: "ignore" }, end: { decision: "ignore" } }])); document.start = "s0"; });
    invalid((document) => { document.select = Array.from({ length: 257 }, () => ({ kind: "invocation" })); });
    invalid((document) => { document.options.namespace.names = Array.from({ length: 17 }, (_, index) => `--option-${index}`); });
    invalid((document) => { document.states.command.cases[0].when = { all: Array.from({ length: 32_769 }, () => true) }; });
    invalid((document) => { document.states.tail.end.audit = { items: Array.from({ length: 4_097 }, () => null) }; });
    expect(() => validatePolicyDocument(withAuditItems(4_095))).not.toThrow();
  });

  test("rejects malformed restricted regular expressions", () => {
    for (const pattern of ["[", "[]", "\\q", "a]", "a+", "^a^", "[z-a]"]) {
      invalid((document) => { document.states.command.cases[0].when = { call: "linearRegex", args: [{ ref: "word" }, pattern] }; });
    }
    expect(() => validatePolicyDocument(withWhen({ call: "linearRegex", args: [{ ref: "word" }, "^[a-zA-Z._-]$"] }))).not.toThrow();
  });

  test("rejects shared fragment DAG expansion before compilation allocates it", () => {
    const document = policy();
    const fragments: Record<string, unknown> = { leaf: { cases: [{ when: true, action: { consume: "word", next: "command" } }] } };
    let previous = "leaf";
    for (let index = 0; index < 12; index++) {
      const left = `left${index}`;
      const right = `right${index}`;
      const next = `join${index}`;
      fragments[left] = { uses: [previous], cases: [] };
      fragments[right] = { uses: [previous], cases: [] };
      fragments[next] = { uses: [left, right], cases: [] };
      previous = next;
    }
    document.fragments = fragments;
    document.states.command.fragments = [previous];
    expect(() => validatePolicyDocument(document)).toThrow("expanded fragment");
  });

  test("freezes a closed v1 catalogue with total documented operations", () => {
    expect(BUILTINS_V1.equals).toMatchObject({ args: ["stringish", "stringish"], result: "bool", complexity: "O(n)" });
    expect(BUILTINS_V1.linearRegex).toMatchObject({ total: true, complexity: "O(n + m)" });
    expect(Object.isFrozen(BUILTINS_V1)).toBeTrue();
  });

  test("documents every closed builtin and the v1 progress proof", () => {
    const documentation = readFileSync(new URL("../docs/policy-dsl.md", import.meta.url), "utf8");
    for (const name of Object.keys(BUILTINS_V1)) expect(documentation).toContain(`\`${name}\``);
    expect(documentation).toContain(POLICY_LANGUAGE_V1);
    expect(documentation).toContain("remaining argv token boundaries plus bytes");
  });

  test("property: generated valid and invalid machines are classified deterministically", () => {
    for (let seed = 0; seed < 256; seed++) {
      const document = policy();
      const stateCount = seed % 12 + 1;
      document.states = Object.fromEntries(Array.from({ length: stateCount }, (_, index) => [
        `state${index}`,
        {
          cases: index + 1 < stateCount ? [{ when: true, action: { consume: "word", next: `state${index + 1}` } }] : [],
          default: { decision: "ignore" },
          end: { decision: "ignore" },
        },
      ]));
      document.start = "state0";
      expect(() => compilePolicyDocument(validatePolicyDocument(document)), `valid seed ${seed}`).not.toThrow();

      (document.states[`state${stateCount - 1}`] as Record<string, any>).cases = [{ when: true, action: { consume: "word", next: "absent" } }];
      expect(() => validatePolicyDocument(document), `invalid seed ${seed}`).toThrow("unknown state");
    }
  });

  test("property: validation work grows linearly with source node count", () => {
    const measures: number[] = [];
    const work: number[] = [];
    for (const stateCount of [8, 16, 32, 64, 128]) {
      const document = policy();
      document.states = Object.fromEntries(Array.from({ length: stateCount }, (_, index) => [
        `state${index}`,
        {
          cases: [{ when: true, action: { consume: "word", next: `state${Math.min(index + 1, stateCount - 1)}` } }],
          default: { decision: "ignore" },
          end: { decision: "ignore" },
        },
      ]));
      document.start = "state0";
      const metrics = validatePolicyDocument(document).metrics;
      measures.push(metrics.nodes);
      work.push(metrics.validationWork);
    }
    expect(measures).toEqual([8, 16, 32, 64, 128].map((count) => expect.any(Number)));
    expect(measures[4]! / measures[0]!).toBeLessThan(20);
    expect(work[4]! / work[0]!).toBeLessThan(20);
  });

  test("property: enum domain equality uses one observable comparison per assignment", () => {
    for (const domainSize of [32, 128, 512]) {
      for (const caseCount of [8, 32, 128]) {
        let comparisons = 0;
        let tableEntries = 0;
        const metrics = validatePolicyDocument(enumAssignmentDocument(caseCount, domainSize), {
          onEnumDomainComparison: () => { comparisons++; },
          onEnumDomainTableEntry: () => { tableEntries++; },
        }).metrics;
        expect(metrics.enumDomainChecks, `domain ${domainSize}, cases ${caseCount}`).toBe(caseCount);
        expect(metrics.enumDomainComparisons, `domain ${domainSize}, cases ${caseCount}`).toBe(caseCount);
        expect(comparisons, `domain ${domainSize}, cases ${caseCount}`).toBe(caseCount);
        expect(tableEntries, `domain ${domainSize}, cases ${caseCount}`).toBe(domainSize * 2);
      }
    }

    let fixedComparisonCalls = 0;
    let fixedTableEntries = 0;
    const fixedDomain = validatePolicyDocument(enumAssignmentDocument(128, 512), {
      onEnumDomainComparison: () => { fixedComparisonCalls++; },
      onEnumDomainTableEntry: () => { fixedTableEntries++; },
    }).metrics;
    let largerComparisonCalls = 0;
    let largerTableEntries = 0;
    const largerDomain = validatePolicyDocument(enumAssignmentDocument(128, 1_024), {
      onEnumDomainComparison: () => { largerComparisonCalls++; },
      onEnumDomainTableEntry: () => { largerTableEntries++; },
    }).metrics;
    expect(largerDomain.enumDomainComparisons).toBe(fixedDomain.enumDomainComparisons);
    expect(largerComparisonCalls).toBe(fixedComparisonCalls);
    expect(fixedTableEntries).toBe(512 * 2);
    expect(largerTableEntries).toBe(1_024 * 2);
    expect(largerDomain.validationWork - fixedDomain.validationWork).toBeLessThan(2_100);
  });

  test("property: cluster options retain every valid form without synthetic unterminated states", () => {
    const forms = ["separate", "attachedShort", "equalsLong", "cluster"];
    for (let mask = 1; mask < 16; mask++) {
      const document = policy();
      document.options.namespace.forms = forms.filter((_, index) => (mask & (1 << index)) !== 0);
      if (!document.options.namespace.forms.includes("attachedShort") && !document.options.namespace.forms.includes("cluster")) {
        document.options.namespace.names = ["--namespace"];
      }
      if (!document.options.namespace.forms.includes("equalsLong")) document.options.namespace.names = ["-n"];
      const compiled = compilePolicyDocument(validatePolicyDocument(document));
      expect(compiled.options.namespace.forms, `mask ${mask}`).toEqual(document.options.namespace.forms);
      expect(Object.values(compiled.states).every((state) => state.default.kind === "terminal" && state.end.kind === "terminal"), `mask ${mask}`).toBeTrue();
    }
  });

  test("property: bounded shared fragment DAGs compile to their exact materialized case count", () => {
    for (let depth = 0; depth < 10; depth++) {
      const document = sharedFragmentDocument(depth);
      const compiled = compilePolicyDocument(validatePolicyDocument(document));
      expect(compiled.states.command.cases.filter((entry) => entry.origin.startsWith("fragment:")).length, `depth ${depth}`).toBe(2 ** depth);
    }
  });
});

function withWhen(when: unknown): Record<string, unknown> {
  const document = policy();
  document.states.command.cases[0].when = when;
  return document;
}

function withAssignment(set: Record<string, unknown>): Record<string, unknown> {
  const document = policy();
  document.states.command.cases[0].action.set = set;
  return document;
}

function sharedFragmentDocument(depth: number): Record<string, unknown> {
  const document = policy();
  const fragments: Record<string, unknown> = { leaf: { cases: [{ when: true, action: { consume: "word", next: "command" } }] } };
  let previous = "leaf";
  for (let index = 0; index < depth; index++) {
    const left = `left${index}`;
    const right = `right${index}`;
    const next = `join${index}`;
    fragments[left] = { uses: [previous], cases: [] };
    fragments[right] = { uses: [previous], cases: [] };
    fragments[next] = { uses: [left, right], cases: [] };
    previous = next;
  }
  document.fragments = fragments;
  document.states.command.fragments = [previous];
  return document;
}

function withAuditItems(count: number): Record<string, unknown> {
  const document = policy();
  document.states.tail.end.audit = { items: Array.from({ length: count }, () => null) };
  return document;
}

function enumAssignmentDocument(caseCount: number, domainSize: number): Record<string, unknown> {
  const document = policy();
  const values = Array.from({ length: domainSize }, (_, index) => `v${index}`);
  document.registers.mode = { type: "enum", values, initial: "v0" };
  document.registers.sourceMode = { type: "enum", values: [...values], initial: "v0" };
  document.states.command.cases = Array.from({ length: caseCount }, () => ({
    when: true,
    action: { consume: "word", next: "command", set: { mode: { ref: "sourceMode" } } },
  }));
  return document;
}
