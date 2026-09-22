import { beforeAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverWasmDir, initBashParser, type LoadedPolicyRuntime, type ValidatedBashPolicy } from "../src/index.ts";
import { evaluateClaudeBashPolicy } from "../adapters/claude-code/_bash_policy.ts";
import { classifyKubectlSecretAudit } from "../adapters/claude-code/kubectl_secret_audit_log.ts";
import { loadClaudeSessionRuntime } from "../adapters/claude-code/bash_policy.ts";

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

test("Claude session manifests keep config immutable and reject changed source bytes", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-claude-session-"));
  const home = join(root, "home");
  const state = join(root, "state");
  const policy = join(root, "policy.policy.mjs");
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "disabled" }, bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 } }));
  const env = { SAFETY_CORE_CONFIG_HOME: home, SAFETY_CORE_STATE_HOME: state };
  const first = await loadClaudeSessionRuntime("session", root, env);
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [join(root, "missing.policy.mjs")], projectPolicies: { mode: "disabled" }, bashAnalysis: first.limits }));
  await expect(loadClaudeSessionRuntime("session", root, env)).resolves.toMatchObject({ limits: first.limits });
  writeFileSync(policy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "defer" }) });\n`);
  await expect(loadClaudeSessionRuntime("session", root, env)).rejects.toThrow("digest changed since session startup");
});

test("Claude startup rejects missing configured policy sources", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-claude-failure-"));
  const home = join(root, "home");
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [join(root, "missing.policy.mjs")], projectPolicies: { mode: "disabled" }, bashAnalysis: { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 } }));
  await expect(loadClaudeSessionRuntime("failed", root, { SAFETY_CORE_CONFIG_HOME: home, SAFETY_CORE_STATE_HOME: join(root, "state") })).rejects.toThrow("cannot canonicalize policy source");
});

test("Claude concurrent first hooks establish exactly one immutable manifest", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-claude-race-"));
  const home = join(root, "home");
  const state = join(root, "state");
  const firstPolicy = join(root, "first.policy.mjs");
  const secondPolicy = join(root, "second.policy.mjs");
  const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(firstPolicy, `await new Promise((resolve) => setTimeout(resolve, 100)); export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
  writeFileSync(secondPolicy, `export default Object.freeze({ apiVersion: 1, layer: "permission", select: Object.freeze([]), evaluate: () => ({ kind: "ignore" }) });\n`);
  const configPath = join(home, "safety-core", "config.json");
  writeFileSync(configPath, JSON.stringify({ version: 1, policies: [firstPolicy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
  const env = { SAFETY_CORE_CONFIG_HOME: home, SAFETY_CORE_STATE_HOME: state };
  const first = loadClaudeSessionRuntime("race", root, env);
  await new Promise((resolve) => setTimeout(resolve, 20));
  writeFileSync(configPath, JSON.stringify({ version: 1, policies: [secondPolicy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
  const runtimes = await Promise.all([first, ...Array.from({ length: 8 }, () => loadClaudeSessionRuntime("race", root, env))]);
  for (const runtime of runtimes) expect(runtime.policySet.sources.map((source) => source.canonicalPath)).toEqual([firstPolicy]);
});

test("Claude audit classifies Kubectl Secret activity without policy reload", () => {
  expect(classifyKubectlSecretAudit("kubectl get Secret application")).toEqual({ kubectl_subcommand: "get", resource: "secret", command_length: "kubectl get Secret application".length });
  expect(classifyKubectlSecretAudit("kubectl get pods; kubectl get secret application")).toEqual({ kubectl_subcommand: "get", resource: "secret", command_length: "kubectl get pods; kubectl get secret application".length });
});
