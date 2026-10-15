import assert from "node:assert/strict";
import { join } from "node:path";

import { Effect } from "effect";
import { Llm, OpenCodeDriver } from "opencode-drive";

import { configHome, executable, isolatedEnvironment, plugin, poll, root } from "./support.ts";

const initialCallID = "call_before_reload";
const reloadedCallID = "call_after_reload";
const initialProjectConfig = `${JSON.stringify({ version: 1, policies: [".safety-core/allow.policy.json"] }, null, 2)}\n`;
const noPolicyProjectConfig = `${JSON.stringify({ version: 1, policies: [] }, null, 2)}\n`;
const allowPolicy = await Bun.file(join(root, "policies/dsl/bash/bash-status.policy.json")).text();

export default OpenCodeDriver.use(
  {
    project: {
      files: {
        ".safety-core/config.json": initialProjectConfig,
        ".safety-core/allow.policy.json": allowPolicy,
      },
    },
    config: { plugins: [plugin] },
    opencode: {
      command: [executable],
      compatibility: "required",
      env: {
        SAFETY_CORE_CONFIG_HOME: configHome("reload"),
        ...isolatedEnvironment(),
      },
    },
  },
  ({ directory, llm, opencode, ui }) =>
    Effect.gen(function* () {
      yield* llm.queue(
        Llm.toolCall({ index: 0, id: initialCallID, name: "shell", input: { command: "true" } }),
        Llm.finish("tool-calls"),
      );
      yield* llm.queue(Llm.text("SAFETY_CORE_BEFORE_RELOAD", { delay: 0 }));
      yield* ui.submit("Run the policy-allowed shell command.");
      yield* ui.waitFor("SAFETY_CORE_BEFORE_RELOAD");

      const sessionID = yield* poll(
        opencode.session.list({ limit: 1, order: "desc" }).pipe(Effect.map((sessions) => sessions.data[0]?.id)),
        "current session",
      );
      const initialPermissions = yield* opencode.permission.list({ sessionID });
      assert.equal(initialPermissions.length, 0, "the initial project policy must allow true without prompting");

      yield* Effect.tryPromise(() => Bun.write(join(directory, ".safety-core/config.json"), noPolicyProjectConfig));
      yield* opencode.session.command({ sessionID, name: "safety-core.policy.reload", text: "" });

      yield* llm.queue(
        Llm.toolCall({ index: 0, id: reloadedCallID, name: "shell", input: { command: "true" } }),
        Llm.finish("tool-calls"),
      );
      yield* llm.queue(Llm.text("SAFETY_CORE_AFTER_RELOAD", { delay: 0 }));
      yield* ui.submit("Run the command after reloading its policy.");
      const permission = yield* poll(
        opencode.permission.list({ sessionID }).pipe(
          Effect.map((requests) => requests.find((request) => request.source?.type === "tool" && request.source.id === reloadedCallID)),
        ),
        "permission prompt after policy reload",
      );
      assert.equal(permission.action, "shell");
      yield* opencode.permission.reply({ sessionID, requestID: permission.id, decision: "once" });
      yield* ui.waitFor("SAFETY_CORE_AFTER_RELOAD");
    }),
);
