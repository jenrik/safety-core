import { beforeAll, expect, test } from "bun:test";
import { discoverWasmDir, initBashParser, type LoadedPolicyRuntime, type ValidatedBashPolicy } from "../src/index.ts";
import { evaluateClaudeBashPolicy } from "../adapters/claude-code/_bash_policy.ts";

const policies: readonly ValidatedBashPolicy[] = [
  { source: { canonicalPath: "/policy/guard" }, layer: "guard", select: [], evaluate: (event) =>
    event.kind === "invocation" && event.executable.kind === "known" && event.executable.value === "cat"
      ? { kind: "deny", reason: [{ kind: "literal", value: "protected read" }] }
      : { kind: "ignore" } },
  { source: { canonicalPath: "/policy/permission" }, layer: "permission", select: [{ kind: "invocation", environmentIndependent: true }], evaluate: (event) =>
    event.kind === "invocation" && event.executable.kind === "known" && event.executable.value === "printf"
      ? { kind: "allow", reason: [{ kind: "literal", value: "safe print" }] }
      : { kind: "ignore" } },
] as const;
const runtime = { config: { bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 } }, policySet: { policies, sources: [] }, limits: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 } } as unknown as LoadedPolicyRuntime;
const event = (command: string) => ({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command } }) as const;

beforeAll(() => initBashParser(discoverWasmDir(import.meta.url)));

test("Claude maps generic allow, deny, and defer without policy-name presentation", () => {
  expect(evaluateClaudeBashPolicy(event("cat credentials.json"), { runtime })).toEqual({ kind: "deny", reason: "protected read" });
  expect(evaluateClaudeBashPolicy(event("printf ok"), { runtime })).toEqual({ kind: "allow", reason: "Bash policy fully covers this command" });
  expect(evaluateClaudeBashPolicy(event("unknown"), { runtime })).toBeUndefined();
});

test("Claude evaluation exceptions are observable to the fatal hook wrapper", () => {
  expect(() => evaluateClaudeBashPolicy(event("printf ok"), { runtime, evaluatePolicies: () => { throw new Error("policy failure"); } })).toThrow("policy failure");
});
