import assert from "node:assert/strict";

import { Effect } from "effect";
import { Llm, OpenCodeDriver } from "opencode-drive";

import { configHome, executable, isolatedEnvironment, plugin, poll } from "./support.ts";

const callID = "call_permission_prompt";

export default OpenCodeDriver.use(
  {
    config: { plugins: [plugin] },
    opencode: {
      command: [executable],
      compatibility: "required",
      // Drive's native default is allow. This proves safety-core elevates a
      // policy-deferred shell call to a one-time human permission request.
      env: {
        SAFETY_CORE_CONFIG_HOME: configHome("default"),
        ...isolatedEnvironment(),
      },
    },
  },
  ({ llm, opencode, ui }) =>
    Effect.gen(function* () {
      yield* llm.queue(
        Llm.toolCall({ index: 0, id: callID, name: "shell", input: { command: "printf permission-prompt" } }),
        Llm.finish("tool-calls"),
      );
      yield* llm.queue(Llm.text("SAFETY_CORE_PERMISSION_PROMPT_RESOLVED", { delay: 0 }));

      yield* ui.submit("Run the policy-deferred shell command.");
      const sessionID = yield* poll(
        opencode.session.list({ limit: 1, order: "desc" }).pipe(Effect.map((sessions) => sessions.data[0]?.id)),
        "current session",
      );
      const permission = yield* poll(
        opencode.permission.list({ sessionID }).pipe(
          Effect.map((requests) => requests.find((request) => request.source?.type === "tool" && request.source.id === callID)),
        ),
        "permission prompt for the deferred shell call",
      );
      assert.equal(permission.action, "shell");
      yield* opencode.permission.reply({ sessionID, requestID: permission.id, decision: "once" });
      yield* ui.waitFor("SAFETY_CORE_PERMISSION_PROMPT_RESOLVED");
    }),
);
