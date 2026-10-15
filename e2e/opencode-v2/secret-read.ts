import assert from "node:assert/strict";
import { resolve } from "node:path";

import { Effect, Stream } from "effect";
import { Llm, OpenCodeDriver } from "opencode-drive";

const root = process.env.SAFETY_CORE_E2E_ROOT;
const plugin = process.env.SAFETY_CORE_OPENCODE_V2_PLUGIN;
if (root === undefined || plugin === undefined)
  throw new Error("Run this scenario through scripts/test-opencode-v2-e2e.ts");

const configHome = resolve(root, "e2e/opencode-v2/fixtures");
const executable = process.env.SAFETY_CORE_OPENCODE_V2_COMMAND ?? "opencode2";

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
      // A simulated model must never initialize an optional network judge.
      env: {
        SAFETY_CORE_CONFIG_HOME: configHome,
        ANTHROPIC_API_KEY: "",
        OPENAI_API_KEY: "",
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
