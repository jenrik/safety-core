import assert from "node:assert/strict";

import { Effect } from "effect";
import { Llm, OpenCodeDriver } from "opencode-drive";

import { configHome, executable, isolatedEnvironment, plugin } from "./support.ts";

type JudgeRequest = {
  readonly path: string;
  readonly body: { readonly model?: unknown };
};

const requests: JudgeRequest[] = [];
const judge = Bun.serve({
  port: 0,
  async fetch(request) {
    const url = new URL(request.url);
    const body = (await request.json()) as { readonly model?: unknown };
    requests.push({ path: url.pathname, body });
    if (url.pathname.endsWith("/messages"))
      return Response.json({ content: [{ type: "text", text: '{"ok":true,"reason":"deterministic test judge"}' }] });
    if (url.pathname.endsWith("/chat/completions"))
      return Response.json({ choices: [{ message: { content: '{"ok":true,"reason":"deterministic test judge"}' } }] });
    return new Response("not found", { status: 404 });
  },
});
const judgeBaseUrl = `http://127.0.0.1:${judge.port}/v1`;

function runJudgeCase(name: string, env: Record<string, string>) {
  return OpenCodeDriver.use(
    {
      config: { plugins: [plugin] },
      opencode: {
        command: [executable],
        compatibility: "required",
        env: {
          SAFETY_CORE_CONFIG_HOME: configHome("judge"),
          ...isolatedEnvironment(env),
        },
      },
    },
    ({ llm, ui }) =>
      Effect.gen(function* () {
        yield* llm.queue(
          Llm.toolCall({
            index: 0,
            id: `call_judge_${name}`,
            name: "shell",
            // This is allowed by the status policy but intentionally matches the judge trigger.
            input: { command: "true credentials" },
          }),
          Llm.finish("tool-calls"),
        );
        yield* llm.queue(Llm.text(`SAFETY_CORE_JUDGE_${name}`, { delay: 0 }));
        yield* ui.submit("Run the deterministic judge selection scenario.");
        yield* ui.waitFor(`SAFETY_CORE_JUDGE_${name}`);
      }),
  );
}

export default Effect.gen(function* () {
  yield* runJudgeCase("ANTHROPIC", {
    ANTHROPIC_API_KEY: "e2e-anthropic-key",
    ANTHROPIC_BASE_URL: judgeBaseUrl,
    OPENAI_API_KEY: "e2e-openai-key",
    OPENAI_BASE_URL: judgeBaseUrl,
  });
  yield* Effect.sync(() => {
    assertJudgeSelection(requests.splice(0), "/v1/messages", "claude-haiku-4-5");
  });

  yield* runJudgeCase("OPENAI", {
    OPENAI_API_KEY: "e2e-openai-key",
    OPENAI_BASE_URL: judgeBaseUrl,
  });
  yield* Effect.sync(() => {
    assertJudgeSelection(requests.splice(0), "/v1/chat/completions", "gpt-4o-mini");
  });
}).pipe(Effect.ensuring(Effect.sync(() => judge.stop(true))));

function assertJudgeSelection(requests: readonly JudgeRequest[], path: string, model: string): void {
  assert.equal(requests.length, 1, "the safety command must invoke exactly one judge");
  assert.equal(requests[0]?.path, path);
  assert.equal(requests[0]?.body.model, model);
}
