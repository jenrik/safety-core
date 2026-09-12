import { describe, expect, test } from "bun:test";

import * as authorization from "../src/authorization.ts";

const limits = {
  maxFunctionDepth: 7,
  maxNestedScriptDepth: 6,
  maxSteps: 5,
  maxWorkItems: 4,
};

describe("Bash adapter verdict mapping", () => {
  test("auto-allows only a complete-safe evaluator result and passes no inherited environment", () => {
    const evaluateBashPermission = (authorization as Record<string, unknown>).evaluateBashPermission as
      | ((status: string, source: string, limits: typeof limits, evaluator: (options: unknown) => unknown) => string)
      | undefined;
    const received: unknown[] = [];

    expect(evaluateBashPermission).toBeFunction();
    expect(evaluateBashPermission!("ask", "TOOL=docker; $TOOL image ls", limits, (options) => {
      received.push(options);
      return { verdict: { kind: "allow" } };
    })).toBe("allow");
    expect(received).toEqual([{
      source: "TOOL=docker; $TOOL image ls",
      limits,
      initialEnvironment: { kind: "unavailable" },
    }]);
  });

  test("neutral and analysis failure leave the native permission status untouched", () => {
    const evaluateBashPermission = (authorization as Record<string, unknown>).evaluateBashPermission as
      | ((status: string, source: string, limits: typeof limits, evaluator: (options: unknown) => unknown) => string)
      | undefined;

    expect(evaluateBashPermission).toBeFunction();
    for (const result of [
      { verdict: { kind: "neutral" } },
      { verdict: { kind: "neutral" }, outcome: { kind: "failure" } },
    ]) {
      expect(evaluateBashPermission!("ask", "DYNAMIC=$UNKNOWN; $DYNAMIC", limits, () => ({
        ...result,
      }))).toBe("ask");
    }
  });

  test("only a proven denial turns a native permission request into deny", () => {
    const evaluateBashPermission = (authorization as Record<string, unknown>).evaluateBashPermission as
      | ((status: string, source: string, limits: typeof limits, evaluator: (options: unknown) => unknown) => string)
      | undefined;

    expect(evaluateBashPermission).toBeFunction();
    expect(evaluateBashPermission!("allow", "unknown-command; cat credentials.json", limits, () => ({
      verdict: { kind: "deny" },
    }))).toBe("deny");
  });

  test("hard-block adapters block only a proven denial", () => {
    const shouldHardBlockBash = (authorization as Record<string, unknown>).shouldHardBlockBash as
      | ((source: string, limits: typeof limits, evaluator: (options: unknown) => unknown) => boolean)
      | undefined;

    expect(shouldHardBlockBash).toBeFunction();
    expect(shouldHardBlockBash!("DYNAMIC=$UNKNOWN; $DYNAMIC", limits, () => ({ verdict: { kind: "neutral" } }))).toBe(false);
    expect(shouldHardBlockBash!("DYNAMIC=$UNKNOWN; cat credentials.json", limits, () => ({ verdict: { kind: "deny" } }))).toBe(true);
  });

  test("adapter-specific mappings preserve neutral/failure status and deny-only hard blocks", () => {
    const mapOpenCodeBashStatus = (authorization as Record<string, unknown>).mapOpenCodeBashStatus as
      | ((status: string, verdict: { kind: string }) => string)
      | undefined;
    const shouldBlockPiBash = (authorization as Record<string, unknown>).shouldBlockPiBash as
      | ((verdict: { kind: string }) => boolean)
      | undefined;
    const mapClaudeBashDecision = (authorization as Record<string, unknown>).mapClaudeBashDecision as
      | ((verdict: { kind: string }) => "allow" | "deny" | undefined)
      | undefined;

    expect(mapOpenCodeBashStatus).toBeFunction();
    expect(shouldBlockPiBash).toBeFunction();
    expect(mapClaudeBashDecision).toBeFunction();
    for (const verdict of [{ kind: "neutral" }, { kind: "failure" }]) {
      expect(mapOpenCodeBashStatus!("ask", verdict)).toBe("ask");
      expect(shouldBlockPiBash!(verdict)).toBe(false);
      expect(mapClaudeBashDecision!(verdict)).toBeUndefined();
    }
    expect(mapOpenCodeBashStatus!("ask", { kind: "allow" })).toBe("allow");
    expect(shouldBlockPiBash!({ kind: "deny" })).toBe(true);
    expect(mapClaudeBashDecision!({ kind: "deny" })).toBe("deny");
  });

  test("property: mapping is deterministic for every status/verdict pair", () => {
    const mapOpenCodeBashStatus = (authorization as Record<string, unknown>).mapOpenCodeBashStatus as
      | ((status: string, verdict: { kind: string }) => string)
      | undefined;
    expect(mapOpenCodeBashStatus).toBeFunction();
    for (const status of ["ask", "allow", "deny"]) {
      for (const kind of ["allow", "deny", "neutral", "failure"]) {
        const expected = kind === "allow" ? "allow" : kind === "deny" ? "deny" : status;
        expect(mapOpenCodeBashStatus!(status, { kind })).toBe(expected);
      }
    }
  });
});
