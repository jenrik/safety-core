import { expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createOpenCodePlugin, blockReason } from "../adapters/opencode.ts";
import { loadPolicyRuntime, type BashPolicyEvaluation, type LoadedPolicyRuntime, type ValidatedBashPolicy } from "../src/index.ts";

const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const runtime = { config: { bashAnalysis: limits }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const deny: BashPolicyEvaluation = { decision: "deny", analysis: { complete: true }, events: [], traces: [{ source: { canonicalPath: "/p/deny" }, layer: "guard", event: {} as never, decision: { kind: "deny", reason: [{ kind: "literal", value: "generic denial" }] } }] };
const allow: BashPolicyEvaluation = { decision: "allow", analysis: { complete: true }, events: [], traces: [] };
const defer: BashPolicyEvaluation = { decision: "defer", analysis: { complete: false }, events: [], traces: [] };

test("OpenCode maps generic allow and deny to native status and leaves defer unchanged", async () => {
  const plugin = await createOpenCodePlugin({ runtime, evaluatePolicies: (_runtime, source) => source === "deny" ? deny : source === "allow" ? allow : defer });
  const output = { status: "ask" };
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "allow" }, output);
  expect(output.status).toBe("allow");
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "deny" }, output);
  expect(output.status).toBe("deny");
  output.status = "ask";
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "defer" }, output);
  expect(output.status).toBe("ask");
  expect(blockReason(deny)).toBe("Blocked by safety policy: generic denial");
});

test("OpenCode supplies plugin cwd and an explicit executable resolver", async () => {
  let context: { readonly cwd?: string; readonly executableFilesystem?: unknown } | undefined;
  const plugin = await createOpenCodePlugin({
    runtime,
    evaluatePolicies: (_runtime, _source, value) => {
      context = value;
      return defer;
    },
  }, undefined, "/workspace");
  await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "id" }, { status: "ask" });
  expect(context).toMatchObject({ cwd: "/workspace", executableFilesystem: expect.any(Object) });
});

test("OpenCode rejects runtime evaluation failures rather than falling back", async () => {
  const plugin = await createOpenCodePlugin({ runtime, evaluatePolicies: () => { throw new Error("policy failure"); } });
  await expect((plugin["tool.execute.before"] as Function)({ tool: "bash" }, { args: { command: "anything" } })).rejects.toThrow("policy failure");
});

test("OpenCode rejects the current permission event and poisons later Bash callbacks", async () => {
  let calls = 0;
  const replies: unknown[] = [];
  const plugin = await createOpenCodePlugin({ runtime, evaluatePolicies: () => { calls++; throw new Error("policy failure"); } }, {
    permission: { reply: async (reply: unknown) => { replies.push(reply); } },
  } as never, "/workspace");
  const event = plugin.event as Function;
  await event({ event: { type: "permission.asked", properties: { id: "first", sessionID: "session", permission: "bash", patterns: ["first"] } } });
  await event({ event: { type: "permission.asked", properties: { id: "second", sessionID: "later-session", permission: "bash", patterns: ["second"] } } });
  expect(calls).toBe(1);
  expect(replies).toEqual([
    { directory: "/workspace", requestID: "first", reply: "reject", message: "Safety policy failed: policy failure" },
    { directory: "/workspace", requestID: "second", reply: "reject", message: "Safety policy failed: policy failure" },
  ]);
  const output = { status: "ask" };
  await (plugin["permission.ask"] as Function)({ type: "bash", sessionID: "session", pattern: "third" }, output);
  expect(output.status).toBe("deny");
  expect(calls).toBe(1);
});

test("OpenCode source-load failure aborts startup", async () => {
  const previous = process.env.SAFETY_CORE_CONFIG_HOME;
  const home = mkdtempSync(join(tmpdir(), "safety-core-opencode-startup-"));
  try {
    process.env.SAFETY_CORE_CONFIG_HOME = home;
    await expect(createOpenCodePlugin()).rejects.toThrow("config.json");
  } finally {
    if (previous === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME; else process.env.SAFETY_CORE_CONFIG_HOME = previous;
  }
});

test("property: OpenCode supplies every exact inherited canary to a real DSL permission policy", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-opencode-environment-"));
  const home = join(root, "home");
  const policy = join(root, "environment.policy.json");
  mkdirSync(join(home, "safety-core"), { recursive: true });
  writeFileSync(policy, JSON.stringify(environmentPermissionPolicy()));
  writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({ version: 1, policies: [policy], projectPolicies: { mode: "disabled" }, bashAnalysis: limits }));
  const loaded = await loadPolicyRuntime(root, { SAFETY_CORE_CONFIG_HOME: home });
  const previous = process.env.CANARY_INHERITED;
  try {
    const plugin = await createOpenCodePlugin({ runtime: loaded }, undefined, root);
    for (let index = 0; index < 64; index++) {
      process.env.CANARY_INHERITED = `exact-inherited-${index}-!$%`;
      const output = { status: "ask" };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "printf canary" }, output);
      expect(output.status, `seed ${index}`).toBe("allow");
    }
    delete process.env.CANARY_INHERITED;
    const output = { status: "ask" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "printf canary" }, output);
    expect(output.status).toBe("ask");
  } finally {
    if (previous === undefined) delete process.env.CANARY_INHERITED; else process.env.CANARY_INHERITED = previous;
  }
});

test("OpenCode startup loads an all-mode project DSL policy from its plugin directory", async () => {
  const previous = process.env.SAFETY_CORE_CONFIG_HOME;
  const root = mkdtempSync(join(tmpdir(), "safety-core-opencode-project-"));
  const home = join(root, "home");
  const project = join(root, "project");
  try {
    mkdirSync(join(home, "safety-core"), { recursive: true });
    mkdirSync(join(project, ".safety-core"), { recursive: true });
    writeFileSync(join(home, "safety-core", "config.json"), JSON.stringify({
      version: 1,
      policies: [],
      projectPolicies: { mode: "all" },
      bashAnalysis: limits,
    }));
    writeFileSync(join(project, ".safety-core", "config.json"), JSON.stringify({ version: 1, policies: ["project.policy.json"] }));
    writeFileSync(join(project, "project.policy.json"), JSON.stringify({
      language: "safety-core/bash-policy-v1", layer: "permission", select: [{ kind: "invocation" }], registers: {}, start: "start",
      states: { start: { cases: [], default: { decision: "ignore" }, end: { decision: "allow", reason: ["project allow"] } } },
    }));
    process.env.SAFETY_CORE_CONFIG_HOME = home;
    await expect(createOpenCodePlugin({}, undefined, project)).resolves.toBeDefined();
  } finally {
    if (previous === undefined) delete process.env.SAFETY_CORE_CONFIG_HOME; else process.env.SAFETY_CORE_CONFIG_HOME = previous;
  }
});

test("property: generic outcomes map deterministically across 1,024 permission requests", async () => {
  const plugin = await createOpenCodePlugin({ runtime, evaluatePolicies: (_runtime, source) =>
    source === "allow" ? allow : source === "deny" ? deny : defer });
  for (let seed = 0; seed < 1_024; seed++) {
    const source = ["allow", "deny", "defer"][seed % 3]!;
    const output = { status: "ask" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: source }, output);
    expect(output.status, `seed ${seed}`).toBe(source === "defer" ? "ask" : source);
  }
});

function environmentPermissionPolicy(): Record<string, unknown> {
  return {
    language: "safety-core/bash-policy-v1",
    layer: "permission",
    select: [{ kind: "invocation" }],
    registers: {}, folds: {}, options: {}, fragments: {}, start: "start",
    states: {
      start: {
        cases: [{
          when: { call: "environmentIsKnown", args: [{ call: "environmentLookup", args: ["CANARY_INHERITED"] }] },
          action: { decision: "allow", reason: ["inherited environment canary"] },
        }],
        default: { decision: "defer" },
        end: { decision: "defer" },
      },
    },
  };
}
