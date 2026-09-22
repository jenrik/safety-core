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
    expect(compiled.metrics.transitions).toBeGreaterThan(0);
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
      measures.push(validatePolicyDocument(document).metrics.nodes);
    }
    expect(measures).toEqual([8, 16, 32, 64, 128].map((count) => expect.any(Number)));
    expect(measures[4]! / measures[0]!).toBeLessThan(20);
  });
});
