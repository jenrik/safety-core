import assert from "node:assert/strict";
import { Effect, Stream } from "effect";
import { Llm, OpenCodeDriver } from "opencode-drive";

import { configHome, executable, isolatedEnvironment, plugin } from "./support.ts";

export default OpenCodeDriver.use(
  {
    project: {
      files: {
        // Deliberately contains no secret value. The filename is the security-relevant input.
        "credentials.json": "{}\n",
      },
    },
    config: { plugins: [plugin] },
    opencode: {
      command: [executable],
      compatibility: "required",
      env: {
        SAFETY_CORE_CONFIG_HOME: configHome("default"),
        ...isolatedEnvironment(),
      },
    },
  },
  ({ llm, opencode, ui }) =>
    Effect.gen(function* () {
      const plugins = yield* opencode.plugin.list();
      assert.ok(
        plugins.data.some((entry) => entry.id === "safety-core" && entry.state.status === "active"),
        "the packaged safety-core V2 plugin must activate",
      );

      yield* llm.serve((request, index) => {
        if (index === 0)
          return Stream.make(
            Llm.toolCall({
              index: 0,
              id: "call_secret_read",
              name: "read",
              input: { path: "credentials.json" },
            }),
            Llm.finish("tool-calls"),
          );
        assert.match(
          JSON.stringify(request.body),
          /Blocked by safety policy/,
          "the model must receive the policy rejection instead of file contents",
        );
        return Stream.make(Llm.text("SAFETY_CORE_SECRET_READ_BLOCKED", { delay: 0 }));
      });

      yield* ui.submit("Read credentials.json");
      yield* ui.waitFor("SAFETY_CORE_SECRET_READ_BLOCKED");
    }),
);
