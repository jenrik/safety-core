import { beforeAll, expect, test } from "bun:test";
import { createOpenCodePlugin } from "../adapters/opencode.ts";
import { createOpenCodeV2Plugin } from "../adapters/opencode-v2.ts";
import {
  analyzeBashWithPolicies,
  checkBashFilePermissions,
  combineBashPermissionVerdicts,
  createOpenCodeBashPreflights,
  initBundledBashParser,
  openCodeBashPermissionStatus,
  OPENCODE_POLICY_RELOAD_COMMAND,
  type BashPolicyEvaluation,
  type HarnessFilePermission,
  type LoadedPolicyRuntime,
  type ValidatedBashPolicy,
} from "../src/index.ts";

beforeAll(initBundledBashParser);
const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const commandPolicy: ValidatedBashPolicy = {
  source: { canonicalPath: "/fixture.policy.json" },
  layer: "permission",
  select: [],
  evaluate: () => ({ kind: "allow", reason: [] }),
};
const runtime = {
  config: { bashAnalysis: limits },
  policySet: { policies: [commandPolicy], sources: [] },
  limits,
} as unknown as LoadedPolicyRuntime;
const evaluation = (decision: "allow" | "defer" | "deny"): BashPolicyEvaluation => ({
  decision,
  events: [],
  traces: [],
  analysis: { complete: true },
});
const identity = { sessionID: "session", callID: "call" };

test("preflight ledger retains every outstanding generation and retires each exactly", () => {
  const calls = createOpenCodeBashPreflights();
  const firstArgs = {};
  const replacementArgs = {};
  const first = calls.begin(identity, "foo >first", "/first", firstArgs);
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "pending" });
  calls.complete(first, evaluation("allow"));
  expect(calls.get(identity)).toMatchObject({ source: "foo >first", cwd: "/first", evaluation: { decision: "allow" } });
  const replacement = calls.begin(identity, "foo >second", "/second", replacementArgs);
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "overlapping-reuse" });
  calls.complete(first, evaluation("allow"));
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "overlapping-reuse" });
  calls.complete(replacement, evaluation("defer"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
  calls.discard(first);
  expect(calls.get(identity)).toBeDefined();
  calls.finish(identity, firstArgs);
  expect(calls.get(identity)).toBeDefined();
  calls.finish(identity, replacementArgs);
  expect(calls.get(identity)).toBeUndefined();
});

test("clear/discard cannot resurrect stale async results and incomplete identities never cache", () => {
  const calls = createOpenCodeBashPreflights();
  for (const context of [{}, { sessionID: "session" }, { callID: "call" }, { sessionID: "", callID: "call" }]) {
    expect(calls.begin(context, "foo", "/workspace")).toBeUndefined();
    expect(calls.get(context)).toBeUndefined();
  }
  const old = calls.begin(identity, "foo", "/workspace");
  calls.clear();
  calls.complete(old, evaluation("allow"));
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "invalidated" });
  const pending = calls.begin(identity, "foo", "/workspace");
  calls.discard(pending);
  calls.complete(pending, evaluation("allow"));
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "invalidated" });
});

test("permission mapping preserves native deny and maps the aggregate command/file defer to ask", () => {
  for (const native of ["allow", "ask", "deny"] as const) {
    expect(openCodeBashPermissionStatus(undefined, native)).toBe(native);
    for (const verdict of ["allow", "defer", "deny"] as const) {
      expect(
        openCodeBashPermissionStatus(
          { kind: "complete", source: "foo", cwd: "/workspace", evaluation: evaluation(verdict) },
          native,
        ),
      ).toBe(native === "deny" ? "deny" : verdict === "defer" ? "ask" : verdict);
    }
  }
});

test("property: every command/file verdict combination is reduced restrictively and independent of file order", async () => {
  const verdicts = ["allow", "defer", "deny"] as const;
  for (const command of verdicts) {
    for (const a of verdicts)
      for (const b of verdicts)
        for (const c of verdicts) {
          const all = [command, a, b, c];
          const expected = all.some((verdict) => verdict === "deny")
            ? "deny"
            : all.some((verdict) => verdict === "defer")
              ? "defer"
              : "allow";
          const result = analyzeBashWithPolicies({
            source: "foo >first >second >third",
            cwd: "/workspace",
            initialEnvironment: { kind: "verified", values: {} },
            policies: [
              {
                ...commandPolicy,
                evaluate: () => (command === "defer" ? { kind: "defer" } : { kind: command, reason: [] }),
              },
            ],
          });
          for (const files of [
            [a, b, c],
            [c, a, b],
            [b, c, a],
          ]) {
            let checked = 0;
            const combined = await checkBashFilePermissions(result, { check: () => files[checked++]! });
            expect(combined.decision).toBe(expected);
            if (command !== "deny")
              expect(combined.filePermissionChecks!.map((check) => check.decision)).toEqual(files);
            expect(combineBashPermissionVerdicts([command, ...files])).toBe(expected);
          }
        }
  }
});

test("both adapters use stored file verdicts instead of rechecking or approving reduced patterns", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    let filePermission: HarnessFilePermission = "ask";
    let evaluated = 0;
    let checked = 0;
    const plugin = await create(
      {
        runtime,
        evaluatePolicies: (loaded, source, context) => {
          evaluated++;
          return analyzeBashWithPolicies({
            source,
            cwd: context?.cwd,
            policies: loaded.policySet.policies,
            initialEnvironment: { kind: "verified", values: {} },
          });
        },
        filePermissions: () => ({
          check: () => {
            checked++;
            return filePermission;
          },
        }),
      },
      undefined,
      "/workspace",
    );
    for (const initial of ["allow", "ask", "deny"]) {
      const output = { status: initial };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, output);
      expect(output.status).toBe(initial);
    }
    expect(evaluated).toBe(0);
    await (plugin["tool.execute.before"] as Function)(
      { tool: "bash", ...identity },
      { args: { command: "foo >out", workdir: "/external" } },
    );
    expect(evaluated).toBe(1);
    expect(checked).toBe(1);
    filePermission = "allow";
    for (const initial of ["allow", "ask", "deny"]) {
      const output = { status: initial };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, output);
      expect(output.status).toBe(initial === "deny" ? "deny" : "ask");
    }
    expect(evaluated).toBe(1);
    expect(checked).toBe(1);
  }
});

test("both adapters discard records on replacement failures, completion events, and every reload attempt", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    const replies: unknown[] = [];
    let reloads = 0;
    const plugin = await create(
      {
        runtime,
        evaluatePolicies: (_loaded, source) => evaluation(source === "deny" ? "deny" : "allow"),
        loadRuntime: async () => {
          if (++reloads === 2) throw new Error("replacement failed");
          return runtime;
        },
      },
      {
        permission: {
          reply: async (reply: unknown) => {
            replies.push(reply);
          },
        },
      } as never,
    );
    let call = 0;
    let currentIdentity = identity;
    let args: Record<string, unknown> = {};
    const before = () => {
      currentIdentity = { sessionID: "session", callID: `call-${++call}` };
      args = { command: "foo >out" };
      return (plugin["tool.execute.before"] as Function)({ tool: "bash", ...currentIdentity }, { args });
    };
    const native = async () => {
      const output = { status: "ask" };
      await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...currentIdentity }, output);
      return output.status;
    };
    expect(await native()).toBe("ask");
    await before();
    expect(await native()).toBe("allow");
    await (plugin["tool.execute.after"] as Function)({ tool: "bash", ...currentIdentity, args }, {});
    expect(await native()).toBe("ask");
    for (const status of ["completed", "error"]) {
      await before();
      await (plugin.event as Function)({
        event: {
          type: "message.part.updated",
          properties: { part: { type: "tool", ...currentIdentity, state: { status } } },
        },
      });
      expect(await native()).toBe("ask");
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      await before();
      await (plugin.event as Function)({
        event: { type: "tui.command.execute", properties: { command: OPENCODE_POLICY_RELOAD_COMMAND } },
      });
      expect(await native()).toBe("ask");
    }
    await before();
    await expect(
      (plugin["tool.execute.before"] as Function)({ tool: "bash", ...currentIdentity }, { args: { command: "deny" } }),
    ).rejects.toThrow();
    expect(await native()).toBe("ask");
    await (plugin.event as Function)({
      event: {
        type: "permission.asked",
        properties: {
          permission: "bash",
          patterns: ["foo"],
          ...currentIdentity,
          id: "request",
          tool: { callID: currentIdentity.callID },
        },
      },
    });
    expect(replies).toHaveLength(0);
  }
});

test("property: independent calls cannot share preflight records and old retries cannot overwrite new ones", () => {
  const calls = createOpenCodeBashPreflights();
  for (let seed = 0; seed < 128; seed++) {
    const context = { sessionID: `session-${seed % 7}`, callID: `call-${seed}` };
    const oldArgs = {};
    const currentArgs = {};
    const old = calls.begin(context, "old >out", "/old", oldArgs);
    const current = calls.begin(context, "new >out", "/new", currentArgs);
    calls.complete(current, evaluation("defer"));
    calls.complete(old, evaluation("allow"));
    expect(calls.get(context)).toMatchObject({ kind: "indeterminate", reason: "overlapping-reuse" });
    expect(calls.get({ ...context, sessionID: "another" })).toBeUndefined();
    calls.finish(context, currentArgs);
    expect(openCodeBashPermissionStatus(calls.get(context), "allow")).toBe("ask");
    calls.finish(context, oldArgs);
    expect(calls.get(context)).toBeUndefined();
  }
});

test("both adapters retain an older pending file ask after a newer generation retires", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    let checks = 0;
    let resolveOlder!: (permission: HarnessFilePermission) => void;
    let started!: () => void;
    const startedOlder = new Promise<void>((resolve) => {
      started = resolve;
    });
    const replies: unknown[] = [];
    const plugin = await create(
      {
        runtime,
        evaluatePolicies: (loaded, source, context) =>
          analyzeBashWithPolicies({
            source,
            cwd: context?.cwd,
            policies: loaded.policySet.policies,
            initialEnvironment: { kind: "verified", values: {} },
          }),
        filePermissions: () => ({
          check: () => {
            if (++checks !== 1) return "allow";
            started();
            return new Promise<HarnessFilePermission>((resolve) => {
              resolveOlder = resolve;
            });
          },
        }),
      },
      {
        permission: {
          reply: async (reply: unknown) => {
            replies.push(reply);
          },
        },
      } as never,
      "/workspace",
    );
    const before = plugin["tool.execute.before"] as Function;
    const after = plugin["tool.execute.after"] as Function;
    const olderArgs = { command: "foo >older" };
    const newerArgs = { command: "foo >newer" };
    const older = before({ tool: "bash", ...identity }, { args: olderArgs });
    await startedOlder;
    await before({ tool: "bash", ...identity }, { args: newerArgs });
    const whileOverlap = { status: "allow" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, whileOverlap);
    expect(whileOverlap.status).toBe("ask");
    await after({ tool: "bash", ...identity, args: newerArgs }, {});
    const stillPending = { status: "allow" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, stillPending);
    expect(stillPending.status).toBe("ask");
    resolveOlder("ask");
    await older;
    const afterNewRetired = { status: "allow" };
    await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, afterNewRetired);
    expect(afterNewRetired.status).toBe("ask");
    await (plugin.event as Function)({
      event: {
        type: "permission.asked",
        properties: {
          permission: "bash",
          patterns: ["foo"],
          ...identity,
          id: "older-request",
          tool: { callID: identity.callID },
        },
      },
    });
    expect(replies).toHaveLength(0);
    expect(checks).toBe(2);
    await after({ tool: "bash", ...identity, args: olderArgs }, {});
  }
});

test("outstanding older denials are retained and late retired tokens cannot modify survivors", () => {
  const calls = createOpenCodeBashPreflights();
  const olderArgs = {};
  const newerArgs = {};
  const older = calls.begin(identity, "foo >older", "/old", olderArgs);
  const newer = calls.begin(identity, "foo >newer", "/new", newerArgs);
  calls.complete(newer, evaluation("allow"));
  calls.finish(identity, newerArgs);
  calls.complete(older, evaluation("deny"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("deny");
  calls.complete(newer, evaluation("allow"));
  calls.discard(newer);
  calls.finish(identity, newerArgs);
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("deny");
  calls.clear();
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("deny");
  calls.finish(identity, olderArgs);
  expect(calls.get(identity)).toBeUndefined();
});

test("property: all completion and retirement permutations retain overlap until the last generation retires", () => {
  const permutations = <T>(values: readonly T[]): T[][] =>
    values.length === 0
      ? [[]]
      : values.flatMap((value, index) =>
          permutations(values.filter((_item, itemIndex) => itemIndex !== index)).map((suffix) => [value, ...suffix]),
        );
  for (const completionOrder of permutations([0, 1, 2])) {
    for (const retirementOrder of permutations([0, 1, 2])) {
      for (const disturbance of ["none", "reload", "uncorrelated"] as const) {
        const calls = createOpenCodeBashPreflights();
        const args = [{}, {}, {}];
        const tokens = args.map((arg, index) => calls.begin(identity, `foo >file-${index}`, `/cwd-${index}`, arg));
        const outstanding = new Set([0, 1, 2]);
        for (let step = 0; step < 3; step++) {
          if (disturbance === "reload") calls.clear();
          if (disturbance === "uncorrelated") calls.finish(identity, {});
          calls.complete(tokens[completionOrder[step]!], evaluation(step === 0 ? "defer" : "allow"));
          expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
          const retired = retirementOrder[step]!;
          calls.finish(identity, args[retired]);
          outstanding.delete(retired);
          for (const stale of retirementOrder.slice(0, step + 1)) {
            calls.complete(tokens[stale], evaluation("allow"));
            calls.discard(tokens[stale]);
            calls.finish(identity, args[stale]);
          }
          if (outstanding.size > 0) expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
          else expect(calls.get(identity)).toBeUndefined();
        }
      }
    }
  }
});

test("an uncorrelated terminal cannot retire any outstanding generation", () => {
  const calls = createOpenCodeBashPreflights();
  const args = [{}, {}];
  const tokens = args.map((arg) => calls.begin(identity, "foo", "/workspace", arg));
  calls.finish(identity, {});
  calls.finish(identity, args[1]);
  calls.complete(tokens[0], evaluation("allow"));
  expect(calls.get(identity)).toMatchObject({ kind: "indeterminate", reason: "ambiguous-terminal" });
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
  calls.finish(identity, args[0]);
  expect(calls.get(identity)).toBeUndefined();
});

test("unknown terminal identity retains a restrictive marker and cannot be undone by late completion", () => {
  const calls = createOpenCodeBashPreflights();
  const args = {};
  const token = calls.begin(identity, "sensitive-source >out", "/workspace", args);
  calls.finish(identity, { ...args });
  calls.complete(token, evaluation("allow"));
  const observation = calls.get(identity);
  expect(observation).toEqual({ kind: "indeterminate", decision: "defer", reason: "ambiguous-terminal" });
  expect(observation).not.toHaveProperty("source");
  expect(observation).not.toHaveProperty("evaluation");
  expect(openCodeBashPermissionStatus(observation, "allow")).toBe("ask");
  calls.complete(token, evaluation("deny"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("deny");
  calls.finish(identity, args);
  expect(calls.get(identity)).toBeUndefined();
});

test("reusing an arguments object cannot turn a stale completion into the newest generation", () => {
  const calls = createOpenCodeBashPreflights();
  const args = {};
  const first = calls.begin(identity, "foo >old", "/old", args);
  calls.complete(first, evaluation("allow"));
  calls.finish(identity, args);
  const retry = calls.begin(identity, "foo >new", "/new", args);
  calls.complete(retry, evaluation("allow"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
  calls.finish(identity, args);
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
});

test("an arguments object shared across distinct calls still identifies each execution separately", () => {
  const calls = createOpenCodeBashPreflights();
  const args = {};
  const other = { sessionID: "session", callID: "other" };
  const first = calls.begin(identity, "foo", "/workspace", args);
  const second = calls.begin(other, "foo", "/workspace", args);
  calls.complete(first, evaluation("allow"));
  calls.complete(second, evaluation("allow"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "ask")).toBe("allow");
  expect(openCodeBashPermissionStatus(calls.get(other), "ask")).toBe("allow");
  calls.finish(identity, args);
  expect(calls.get(identity)).toBeUndefined();
  expect(calls.get(other)).toMatchObject({ kind: "complete" });
  calls.finish(other, args);
  expect(calls.get(other)).toBeUndefined();
  const retry = calls.begin(identity, "foo", "/workspace", args);
  calls.complete(retry, evaluation("allow"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
});

test("overlapping permission generations cannot authorize an old request using a newer allow", () => {
  const calls = createOpenCodeBashPreflights();
  const firstArgs = {};
  const retryArgs = {};
  const first = calls.begin(identity, "foo >protected", "/workspace", firstArgs);
  calls.complete(first, evaluation("defer"));
  const retry = calls.begin(identity, "foo >allowed", "/workspace", retryArgs);
  calls.complete(retry, evaluation("allow"));
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
  calls.finish(identity, firstArgs);
  expect(openCodeBashPermissionStatus(calls.get(identity), "allow")).toBe("ask");
  calls.finish(identity, retryArgs);
  expect(calls.get(identity)).toBeUndefined();
});

test("both adapters prevent stale terminal callbacks from dropping a pending retry's file ask", async () => {
  for (const create of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    for (const terminal of ["after-known", "after-missing", "event-known", "event-copy"] as const) {
      for (const retired of [false, true])
        for (const permission of ["allow", "ask"] as const) {
          let checks = 0;
          let resolveCheck!: (permission: HarnessFilePermission) => void;
          let started!: () => void;
          const checkStarted = new Promise<void>((resolve) => {
            started = resolve;
          });
          const replies: unknown[] = [];
          const plugin = await create(
            {
              runtime,
              evaluatePolicies: (loaded, source, context) =>
                analyzeBashWithPolicies({
                  source,
                  cwd: context?.cwd,
                  policies: loaded.policySet.policies,
                  initialEnvironment: { kind: "verified", values: {} },
                }),
              filePermissions: () => ({
                check: () => {
                  if (++checks === 1) return "allow";
                  started();
                  return new Promise<HarnessFilePermission>((resolve) => {
                    resolveCheck = resolve;
                  });
                },
              }),
            },
            {
              permission: {
                reply: async (reply: unknown) => {
                  replies.push(reply);
                },
              },
            } as never,
            "/workspace",
          );
          const firstArgs = { command: "foo >first" };
          const retryArgs = { command: "foo >second" };
          const before = plugin["tool.execute.before"] as Function;
          const after = plugin["tool.execute.after"] as Function;
          const event = plugin.event as Function;
          await before({ tool: "bash", ...identity }, { args: firstArgs });
          if (retired) await after({ tool: "bash", ...identity, args: firstArgs }, {});
          const retry = before({ tool: "bash", ...identity }, { args: retryArgs });
          await checkStarted;
          if (terminal.startsWith("after"))
            await after({ tool: "bash", ...identity, ...(terminal === "after-known" ? { args: firstArgs } : {}) }, {});
          else
            await event({
              event: {
                type: "message.part.updated",
                properties: {
                  part: {
                    type: "tool",
                    ...identity,
                    state: { status: "completed", input: terminal === "event-known" ? firstArgs : { ...firstArgs } },
                  },
                },
              },
            });
          const pending = { status: "allow" };
          await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, pending);
          expect(pending.status, `${terminal}, retired=${retired}`).toBe("ask");
          resolveCheck(permission);
          await retry;
          const output = { status: "allow" };
          await (plugin["permission.ask"] as Function)({ type: "bash", pattern: "foo", ...identity }, output);
          const correlated = terminal === "after-known" || terminal === "event-known";
          const expected = retired && correlated && permission === "allow" ? "allow" : "ask";
          expect(output.status, `${terminal}, retired=${retired}, permission=${permission}`).toBe(expected);
          if (expected === "ask") {
            await event({
              event: {
                type: "permission.asked",
                properties: {
                  permission: "bash",
                  patterns: ["foo"],
                  ...identity,
                  id: "request",
                  tool: { callID: identity.callID },
                },
              },
            });
            expect(replies).toHaveLength(0);
          }
          expect(checks).toBe(2);
          await after({ tool: "bash", ...identity, args: retryArgs }, {});
        }
    }
  }
});

test("property: stale completions cannot retire new records across serial reuse and reload", () => {
  for (let seed = 0; seed < 128; seed++) {
    const calls = createOpenCodeBashPreflights();
    const context = { sessionID: `session-${seed % 7}`, callID: `call-${seed}` };
    const oldArgs = {};
    const args = {};
    const old = calls.begin(context, "old >out", "/old", oldArgs);
    calls.complete(old, evaluation("allow"));
    if (seed % 2 === 0) calls.finish(context, oldArgs);
    else calls.clear();
    const current = calls.begin(context, "new >out", "/new", args);
    if (seed % 3 === 0) calls.complete(current, evaluation("defer"));
    calls.finish(context, oldArgs);
    calls.complete(old, evaluation("allow"));
    calls.discard(old);
    calls.complete(current, evaluation("defer"));
    expect(openCodeBashPermissionStatus(calls.get(context), "allow")).toBe("ask");
    calls.finish(context, args);
    expect(calls.get(context)).toBeUndefined();
  }
});

test("session deletion removes lifecycle markers only for that session", () => {
  const calls = createOpenCodeBashPreflights();
  for (const sessionID of ["first", "second"]) calls.begin({ sessionID, callID: "call" }, "foo", "/workspace");
  calls.clear();
  calls.clearSession("first");
  expect(calls.get({ sessionID: "first", callID: "call" })).toBeUndefined();
  expect(calls.get({ sessionID: "second", callID: "call" })).toMatchObject({ kind: "indeterminate" });
});
