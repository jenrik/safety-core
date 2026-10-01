import { beforeAll, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createOpenCodePlugin } from "../adapters/opencode.ts";
import { createOpenCodeV2Plugin } from "../adapters/opencode-v2.ts";
import {
  analyzeBashWithPolicies, createOpenCodeFilePermissions, evaluateOpenCodePermission,
  initBundledBashParser, type ExecutableFilesystem, type HarnessFileAccessRequest, type LoadedPolicyRuntime,
  type OpenCodePermissionClient, type OpenCodePermissionRule, type ValidatedBashPolicy,
} from "../src/index.ts";

beforeAll(initBundledBashParser);
const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const commandPolicy: ValidatedBashPolicy = { source: { canonicalPath: "/command.policy.json" }, layer: "permission", select: [],
  evaluate: () => ({ kind: "allow", reason: [{ kind: "literal", value: "command allowed" }] }) };
const runtime = { config: { bashAnalysis: limits }, policySet: { policies: [commandPolicy], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
const evaluatePolicies = (loaded: LoadedPolicyRuntime, source: string, context?: { cwd?: string }) =>
  analyzeBashWithPolicies({ policies: loaded.policySet.policies, source, limits, cwd: context?.cwd, initialEnvironment: { kind: "verified", values: {} } });

const filesystem: ExecutableFilesystem = {
  lstat(path) {
    return ["/workspace", "/workspace/sub", "/external"].includes(path)
      ? { kind: "entry", entry: { kind: "directory" } } : { kind: "missing" };
  },
};
const rule = (permission: string, pattern: string, action: "allow" | "ask" | "deny"): OpenCodePermissionRule => ({ permission, pattern, action });
const access = (path: string, operation: "read" | "write" = "write"): HarnessFileAccessRequest => ({ path, operation, effect: operation === "read" ? "read" : "truncate", cwd: "/workspace", span: { start: 0, end: 1 } });
function sdk(rules: readonly OpenCodePermissionRule[], agent = "build", permission: unknown = []) {
  let prompts = 0;
  return {
    app: { agents: async () => ({ data: [{ name: agent, permission: rules }, { name: "other", permission: [rule("*", "*", "allow")] }] }) },
    session: {
      get: async () => ({ data: { permission } }),
      messages: async () => ({ data: [{ info: { role: "assistant", agent }, parts: [{ type: "tool", callID: "call" }] }] }),
      permission: { create: async () => { prompts++; throw new Error("must not create native permission request"); } },
    },
    permission: { reply: async () => { prompts++; } },
    get prompts() { return prompts; },
  };
}

test("native read/edit rules use worktree-relative resources and last matching rule", async () => {
  for (const [action, expected] of [["allow", "allow"], ["ask", "defer"], ["deny", "deny"]] as const) {
    const client = sdk([rule("*", "*", "allow"), rule("edit", "out", action), rule("read", "input", "deny")]);
    const checker = createOpenCodeFilePermissions(client, { sessionID: "session", callID: "call", directory: "/workspace" });
    expect(await checker.check(access("/workspace/out"))).toBe(expected);
    expect(await checker.check(access("/workspace/unrestricted"))).toBe("allow");
    expect(await checker.check(access("/workspace/input", "read"))).toBe("deny");
    expect(client.prompts).toBe(0);
  }
});

test("native external-directory ask/deny checks are independent of file modification allow", async () => {
  for (const [action, expected] of [["allow", "allow"], ["ask", "defer"], ["deny", "deny"]] as const) {
    const client = sdk([rule("*", "*", "allow"), rule("external_directory", "/external/*", action)]);
    const checker = createOpenCodeFilePermissions(client, { sessionID: "session", callID: "call", directory: "/workspace" });
    expect(await checker.check(access("/external/out"))).toBe(expected);
    expect(await checker.check(access("/workspace/out"))).toBe("allow");
    expect(client.prompts).toBe(0);
  }
});

test("/dev/null goes through native modification and external-directory rules", async () => {
  for (const [action, expected] of [["allow", "allow"], ["ask", "defer"], ["deny", "deny"]] as const) {
    const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("edit", "../dev/null", action)]),
      { sessionID: "session", callID: "call", directory: "/workspace" });
    expect(await checker.check(access("/dev/null"))).toBe(expected);
  }
  const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("external_directory", "/dev/*", "ask")]),
    { sessionID: "session", callID: "call", directory: "/workspace" });
  expect(await checker.check(access("/dev/null"))).toBe("defer");
});

test("native context uses the exact originating assistant agent and session rules", async () => {
  const client = sdk([rule("*", "*", "allow"), rule("edit", "*", "deny")], "plan", [rule("read", "*", "ask")]);
  const checker = createOpenCodeFilePermissions(client, { sessionID: "session", callID: "call", directory: "/workspace" });
  expect(await checker.check(access("/workspace/out"))).toBe("deny");
  expect(await checker.check(access("/workspace/out", "read"))).toBe("defer");
});

test("missing native context, unknown SDK shapes, and failures defer without prompting", async () => {
  const client = sdk([rule("*", "*", "allow")]);
  const variants: Array<OpenCodePermissionClient | undefined> = [undefined, {},
    sdk([rule("*", "*", "allow")], "build", {}),
    { ...client, app: { agents: async () => ({ data: [{ name: "build", permission: { edit: "allow" } }] }) } },
    { ...client, session: { ...client.session, messages: async () => ({ data: [] }) } },
    { ...client, app: { agents: async () => { throw new Error("offline"); } } },
  ];
  for (const variant of variants) {
    const checker = createOpenCodeFilePermissions(variant, { sessionID: "session", callID: "call", directory: "/workspace" });
    expect(await checker.check(access("/workspace/out"))).toBe("defer");
  }
  expect(await createOpenCodeFilePermissions(client, { directory: "/workspace" }).check(access("/workspace/out"))).toBe("defer");
  expect(client.prompts).toBe(0);
});

test("a root worktree does not suppress lexical external-directory permissions", async () => {
  for (const worktree of ["/", "/./", "//"]) {
    const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("external_directory", "/external/*", "deny")]),
      { sessionID: "session", callID: "call", directory: "/workspace", worktree });
    expect(await checker.check(access("/external/out")), worktree).toBe("deny");
    expect(await checker.check(access("/workspace/out")), worktree).toBe("allow");
  }
});

test("lexically external paths stay external regardless of a symlink's observed or changed target", async () => {
  const root = mkdtempSync(join(tmpdir(), "safety-core-lexical-files-"));
  try {
    const directory = join(root, "workspace");
    const external = join(root, "external");
    const other = join(root, "other");
    for (const path of [directory, external, other]) mkdirSync(path);
    const link = join(external, "link");
    const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("external_directory", `${external}/*`, "deny")]),
      { sessionID: "session", callID: "call", directory });
    symlinkSync(directory, link);
    expect(await checker.check(access(join(link, "out")))).toBe("deny");
    unlinkSync(link);
    symlinkSync(other, link);
    expect(await checker.check(access(join(link, "out")))).toBe("deny");
    unlinkSync(link);
    expect(await checker.check(access(join(link, "out")))).toBe("deny");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("file permission resources are lexical identities, not filesystem-existence or target proofs", async () => {
  const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("edit", "out", "deny")]),
    { sessionID: "session", callID: "call", directory: "/workspace" });
  expect(await checker.check(access("/workspace/link/../out"))).toBe("deny");
  expect(await checker.check(access("/workspace/nonexistent-parent/out"))).toBe("allow");
  expect(await checker.check(access("relative/out"))).toBe("defer");
  const unknownRoot = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow")]),
    { sessionID: "session", callID: "call", directory: "relative/workspace" });
  expect(await unknownRoot.check(access("/workspace/out"))).toBe("defer");
});

test("both adapters preserve redirect permission decisions across preflight, permission hook and event", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    for (const [action, expected] of [["allow", "allow"], ["ask", "ask"], ["deny", "deny"]] as const) {
      const client = sdk([rule("*", "*", "allow"), rule("edit", "sub/out", action)]);
      const plugin = await create({ runtime, evaluatePolicies, executableFilesystem: filesystem }, client as never, "/workspace");
      const input = { tool: "bash", sessionID: "session", callID: "call" };
      const output = { args: { command: "foo >out", workdir: "sub" } };
      if (action === "deny") {
        await expect((plugin["tool.execute.before"] as Function)(input, output)).rejects.toThrow("harness denied");
      } else {
        await (plugin["tool.execute.before"] as Function)(input, output);
        const permission = { status: "ask" };
        // Native command-prefix patterns must not discard original redirects
        // or the per-call workdir when making the policy decision.
        await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", sessionID: "session", callID: "call" }, permission);
        expect(permission.status).toBe(expected);
        if (action === "ask") {
          await (plugin.event as Function)({ event: { type: "permission.asked", properties: {
            permission: "bash", patterns: ["foo"], sessionID: "session", id: "request", tool: { callID: "call" },
          } } });
          expect(client.prompts).toBe(0);
        }
        await (plugin["tool.execute.after"] as Function)({ ...input, args: output.args }, {});
      }
    }
  }
});

test("adapter host-provided file checker gets actual per-call cwd and cannot override command denial", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    const requests: HarnessFileAccessRequest[] = [];
    const plugin = await create({ runtime, evaluatePolicies, filePermissions: () => ({ check: (request) => { requests.push(request); return "ask"; } }) }, undefined, "/workspace");
    await (plugin["tool.execute.before"] as Function)({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "foo >out", workdir: "/external" } });
    expect(requests[0]).toMatchObject({ path: "/external/out", cwd: "/external" });
    let checked = 0;
    const deniedRuntime = { ...runtime, policySet: { ...runtime.policySet, policies: [{ ...commandPolicy, evaluate: () => ({ kind: "deny", reason: [] }) }] } } as LoadedPolicyRuntime;
    const denied = await create({ runtime: deniedRuntime, evaluatePolicies, filePermissions: () => ({ check: () => { checked++; return "allow"; } }) }, undefined, "/workspace");
    await expect((denied["tool.execute.before"] as Function)({ tool: "bash" }, { args: { command: "foo >out" } })).rejects.toThrow();
    expect(checked).toBe(0);
  }
});

test("property: exact native rule order and path glob matching preserve explicit ask over broad allow", () => {
  for (let seed = 0; seed < 256; seed++) {
    const file = `dir-${seed}/file.txt`;
    const glob = `dir-${seed}/f?le.*`;
    expect(evaluateOpenCodePermission("edit", file, [rule("*", "*", "allow"), rule("edit", glob, "ask")]), `seed ${seed}`).toBe("ask");
    expect(evaluateOpenCodePermission("edit", file, [rule("edit", glob, "deny"), rule("*", "*", "allow")]), `seed ${seed}`).toBe("allow");
    expect(evaluateOpenCodePermission("read", file, [rule("edit", glob, "deny")]), `seed ${seed}`).toBe("ask");
  }
});

test("property: lexical normalization preserves external-directory decisions without filesystem observations", async () => {
  for (let seed = 0; seed < 64; seed++) {
    for (const worktree of [undefined, "/", "/workspace"]) {
      for (const [action, expected] of [["allow", "allow"], ["ask", "defer"], ["deny", "deny"]] as const) {
        const checker = createOpenCodeFilePermissions(sdk([rule("*", "*", "allow"), rule("external_directory", "/external/*", action)]),
          { sessionID: "session", callID: "call", directory: "/workspace", worktree });
        for (const path of [`/external/dir-${seed}/out`, `/workspace/../external/dir-${seed}/out`, `/external/./dir-${seed}/out`]) {
          expect(await checker.check(access(path)), `${worktree ?? "unset"}: ${path}`).toBe(expected);
        }
      }
    }
  }
});
