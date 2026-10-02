import { describe, expect, test } from "bun:test";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { POLICY_LANGUAGE_V1, POLICY_LANGUAGE_V2, validatePolicyDocument } from "../src/policy/dsl/validate.ts";
import type { InvocationView } from "../src/policy/types.ts";

type Word =
  | { readonly kind: "known"; readonly value: string }
  | { readonly kind: "unknown"; readonly reason: { readonly kind: string } };

function invocation(argv: readonly Word[]): InvocationView {
  return {
    kind: "invocation",
    executable: { kind: "known", value: "tool" },
    executionTarget: "external-path",
    executableIdentity: {
      qualification: "incomplete",
      spelling: "tool",
      basename: "tool",
      chain: [],
      failure: { kind: "not-found" },
    },
    argv,
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  };
}

const known = (value: string): Word => ({ kind: "known", value });
const unknown: Word = { kind: "unknown", reason: { kind: "expansion" } };
const atEnd = { call: "atEndOfWord", args: [] };
const span = { call: "span", args: [{ ref: "begin" }, { ref: "cursor" }] };
const defer = { decision: "defer" };
const allow = { decision: "allow", reason: ["captured: ", { ref: "piece" }] };

function document(): Record<string, any> {
  return {
    language: POLICY_LANGUAGE_V2,
    layer: "permission",
    select: [{ kind: "invocation" }],
    registers: {
      begin: { type: "location", initial: null },
      piece: { type: "inputRef", initial: null },
    },
    options: {},
    start: "start",
    states: {
      start: {
        cases: [
          {
            when: { call: "equals", args: [{ ref: "byte" }, "="] },
            action: { consume: "byte", next: "skip", set: { begin: { ref: "cursor" } } },
          },
          { when: true, action: { consume: "byte", next: "scan", set: { begin: { ref: "cursor" } } } },
        ],
        default: defer,
        end: defer,
      },
      skip: {
        cases: [
          {
            when: true,
            action: {
              consume: "restOfWord",
              next: "finished",
              set: { piece: { call: "span", args: [{ ref: "begin" }, { ref: "begin" }] } },
            },
          },
        ],
        default: defer,
        end: defer,
      },
      scan: {
        cases: [
          { when: atEnd, action: { consume: "word", next: "finished", set: { piece: span } } },
          {
            when: { call: "equals", args: [{ ref: "byte" }, "="] },
            action: { consume: "restOfWord", next: "finished", set: { piece: span } },
          },
          { when: true, action: { consume: "byte", next: "scan" } },
        ],
        default: defer,
        end: defer,
      },
      finished: { cases: [], default: defer, end: allow },
    },
  };
}

function compile(source: Record<string, any> = document()) {
  return createDslPolicy(compilePolicyDocument(validatePolicyDocument(source)), "/policy/intra-word.policy.json");
}

describe("DCRM v2 intra-word language", () => {
  test("preserves the versioned v1 boundary", () => {
    const v1 = document();
    v1.language = POLICY_LANGUAGE_V1;
    expect(() => validatePolicyDocument(v1)).toThrow("location");
    v1.registers = {};
    expect(() => validatePolicyDocument(v1)).toThrow("byte");
    v1.states = {
      start: { cases: [{ when: atEnd, action: { decision: "deny", reason: ["end"] } }], default: defer, end: defer },
    };
    expect(() => validatePolicyDocument(v1)).toThrow("atEndOfWord");

    const v2 = compilePolicyDocument(validatePolicyDocument(document()));
    expect(v2.states.start.cases[0]?.action).toMatchObject({ consume: "byte", progress: 1 });
    expect(v2.states.scan.cases[1]?.action).toMatchObject({ consume: "restOfWord", progress: 1 });

    const legacy = document();
    legacy.language = POLICY_LANGUAGE_V1;
    legacy.registers = { byte: { type: "inputRef", initial: null }, cursor: { type: "inputRef", initial: null } };
    legacy.states = {
      start: {
        cases: [
          {
            when: true,
            action: { consume: "word", next: "done", set: { byte: { ref: "word" }, cursor: { ref: "word" } } },
          },
        ],
        default: defer,
        end: defer,
      },
      done: { cases: [], default: defer, end: { decision: "allow", reason: [{ ref: "byte" }, { ref: "cursor" }] } },
    };
    expect(compile(legacy).evaluate(invocation([known("legacy")]))).toMatchObject({
      kind: "allow",
      reason: [
        { kind: "value", value: "legacy" },
        { kind: "value", value: "legacy" },
      ],
    });
    legacy.language = POLICY_LANGUAGE_V2;
    expect(() => validatePolicyDocument(legacy)).toThrow("reserved");
  });

  test("captures a byte-span for later diagnostics and can explicitly skip a suffix", () => {
    const policy = compile();
    expect(policy.evaluate(invocation([known("route")]))).toMatchObject({
      kind: "allow",
      reason: [
        { kind: "literal", value: "captured: " },
        { kind: "value", value: "route" },
      ],
    });
    expect(policy.evaluate(invocation([known("route=unreviewed")]))).toMatchObject({
      kind: "allow",
      reason: [
        { kind: "literal", value: "captured: " },
        { kind: "value", value: "route" },
      ],
    });
    expect(policy.evaluate(invocation([known("=unreviewed")]))).toMatchObject({
      kind: "allow",
      reason: [
        { kind: "literal", value: "captured: " },
        { kind: "value", value: "" },
      ],
    });
    expect(policy.evaluate(invocation([known("route"), known("extra")])).kind).toBe("defer");
    expect(policy.evaluate(invocation([known("")])).kind).toBe("defer");
    expect(policy.evaluate(invocation([unknown])).kind).toBe("defer");
    expect(policy.evaluate(invocation([])).kind).toBe("defer");
  });

  test("requires an explicit skip or exact end before a partially inspected word can advance", () => {
    const source = document();
    source.states.scan.cases.unshift({ when: true, action: { consume: "word", next: "finished" } });
    const policy = compile(source);
    expect(policy.evaluate(invocation([known("foo")])).kind).toBe("defer");

    const skipAtBoundary = document();
    skipAtBoundary.states.start.cases[1].action.consume = "restOfWord";
    expect(compile(skipAtBoundary).evaluate(invocation([known("foo")])).kind).toBe("defer");
  });

  test("does not apply word-level options in the middle of a word", () => {
    const source = document();
    source.registers.optionSeen = { type: "bool", initial: false };
    source.options = {
      middle: { names: ["-X"], value: "absent", forms: [], availableIn: ["scan"], set: { optionSeen: true } },
    };
    source.states.start.cases = [{ when: true, action: { consume: "byte", next: "scan" } }];
    source.states.scan.cases = [
      { when: { call: "equals", args: [{ ref: "byte" }, "X"] }, action: { consume: "byte", next: "finished" } },
    ];
    source.states.finished.cases = [{ when: atEnd, action: { consume: "word", next: "done" } }];
    source.states.done = { cases: [], default: defer, end: { decision: "allow", reason: ["scanned"] } };
    expect(compile(source).evaluate(invocation([known("-X")])).kind).toBe("allow");
    const result = compile(source).evaluateWithTrace(invocation([known("-X")]));
    expect(result.steps.some((step) => step.action === "option")).toBe(false);
  });

  test("keeps short-option cluster parsing separate from authored byte parsing", () => {
    const source = document();
    source.options = {
      a: { names: ["-a"], value: "absent", forms: [], availableIn: "*" },
      x: { names: ["-x"], value: "absent", forms: [], availableIn: "*" },
    };
    const policy = compile(source);
    const knownCluster = policy.evaluateWithTrace(invocation([known("-ax")]));
    expect(knownCluster.steps.filter((step) => step.action === "option")).toHaveLength(2);
    expect(knownCluster.decision.kind).toBe("defer");
    const partialCluster = policy.evaluateWithTrace(invocation([known("-az")]));
    expect(partialCluster.steps).toMatchObject([{ action: "option" }, { action: "terminal", decision: "defer" }]);
  });

  test("refuses spans across different arguments and in reverse order", () => {
    const across = document();
    across.states.scan.cases = [
      { when: atEnd, action: { consume: "word", next: "other" } },
      { when: true, action: { consume: "byte", next: "scan" } },
    ];
    across.states.other = {
      cases: [
        {
          when: { call: "equals", args: [{ call: "span", args: [{ ref: "begin" }, { ref: "cursor" }] }, "first"] },
          action: { decision: "allow", reason: ["same word"] },
        },
      ],
      default: defer,
      end: defer,
    };
    expect(compile(across).evaluate(invocation([known("first"), known("second")])).kind).toBe("defer");

    const reverse = document();
    reverse.registers.earlier = { type: "location", initial: null };
    reverse.states.start.cases[1].action.set = { earlier: { ref: "cursor" } };
    reverse.states.scan.cases[0].when = {
      all: [
        atEnd,
        { call: "equals", args: [{ call: "span", args: [{ ref: "cursor" }, { ref: "earlier" }] }, "anything"] },
      ],
    };
    reverse.states.scan.cases.splice(1, 1);
    expect(compile(reverse).evaluate(invocation([known("anything")])).kind).toBe("defer");
  });

  test("counts UTF-8 bytes and does not turn a split code point into a matching replacement character", () => {
    const whole = compile().evaluate(invocation([known("é")]));
    expect(whole).toMatchObject({
      kind: "allow",
      reason: [
        { kind: "literal", value: "captured: " },
        { kind: "value", value: "é" },
      ],
    });

    const source = document();
    source.states.start.cases = [
      { when: true, action: { consume: "byte", next: "cut", set: { begin: { ref: "cursor" } } } },
    ];
    source.states.cut = {
      cases: [{ when: { call: "equals", args: [span, "�"] }, action: { decision: "allow", reason: ["replacement"] } }],
      default: defer,
      end: defer,
    };
    expect(compile(source).evaluate(invocation([known("é")])).kind).toBe("defer");
  });

  test("validates location typing and rejects string construction or invalid transition kinds", () => {
    for (const mutate of [
      (source: Record<string, any>) => {
        source.states.start.cases[1].action.set.begin = { ref: "word" };
      },
      (source: Record<string, any>) => {
        source.states.start.cases[1].action.set.begin = 1;
      },
      (source: Record<string, any>) => {
        source.states.start.cases[1].action.consume = "rewind";
      },
      (source: Record<string, any>) => {
        source.states.scan.cases[0].when = { call: "span", args: ["not a location", { ref: "cursor" }] };
      },
      (source: Record<string, any>) => {
        source.registers.begin.initial = 0;
      },
    ]) {
      const source = document();
      mutate(source);
      expect(() => validatePolicyDocument(source)).toThrow();
    }
  });

  test("recognizes an exact endpoint rather than treating a matching prefix as sufficient", () => {
    const source = document();
    source.registers = {};
    source.states = {};
    const endpoint = "/access/api/v2/permissions";
    for (const [index, character] of [...endpoint].entries()) {
      source.states[`s${index}`] = {
        cases: [
          {
            when: { call: "equals", args: [{ ref: "byte" }, character] },
            action: { consume: "byte", next: `s${index + 1}` },
          },
        ],
        default: defer,
        end: defer,
      };
    }
    source.states[`s${endpoint.length}`] = {
      cases: [{ when: atEnd, action: { consume: "word", next: "done" } }],
      default: defer,
      end: defer,
    };
    source.states.done = { cases: [], default: defer, end: { decision: "allow", reason: ["exact route"] } };
    source.start = "s0";
    const policy = compile(source);
    expect(policy.evaluate(invocation([known(endpoint)])).kind).toBe("allow");
    for (const route of [
      "/access/api/v2/permission",
      `${endpoint}/other`,
      `${endpoint}?page=1`,
      `${endpoint}%2Fother`,
      `${endpoint}.`,
      "",
    ]) {
      expect(policy.evaluate(invocation([known(route)])).kind, route).toBe("defer");
    }
    for (let index = 0; index < endpoint.length; index++) {
      expect(policy.evaluate(invocation([known(endpoint.slice(0, index))])).kind, String(index)).toBe("defer");
    }
  });

  test("property: every consumed byte advances, and capture equals the scanned prefix", () => {
    const policy = compile();
    let seed = 0x1a2b3c4d;
    for (let trial = 0; trial < 128; trial++) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      const length = 1 + (seed % 80);
      let word = "";
      for (let index = 0; index < length; index++) {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        word += "abc=/%"[seed % 6]!;
      }
      const result = policy.evaluateWithTrace(invocation([known(word)]));
      expect(result.decision.kind, word).toBe("allow");
      expect(result.decision.kind === "allow" && result.decision.reason[1]).toMatchObject({
        kind: "value",
        value: word.split("=", 1)[0],
      });
      expect(result.steps.length, word).toBeLessThanOrEqual(Buffer.byteLength(word) + 2);
      for (let i = 1; i < result.steps.length; i++) {
        const before = result.steps[i - 1]!;
        const after = result.steps[i]!;
        expect(after.argvIndex > before.argvIndex || after.wordByteOffset! >= before.wordByteOffset!, word).toBe(true);
      }
    }
  });
});
