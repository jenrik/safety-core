import { expect, test } from "bun:test";

import { createAnthropicJudge, createOpenAIJudge } from "../adapters/opencode-judge.ts";

test("OpenCode judge factories own provider HTTP requests and use core parsing", async () => {
  const requests: Array<{ path: string; body: Record<string, unknown> }> = [];
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const body = (await request.json()) as Record<string, unknown>;
      requests.push({ path: new URL(request.url).pathname, body });
      return Response.json(
        new URL(request.url).pathname.endsWith("/messages")
          ? { content: [{ type: "text", text: '{"ok":false,"reason":"Anthropic denied"}' }] }
          : { choices: [{ message: { content: '{"ok":false,"reason":"OpenAI denied"}' } }] },
      );
    },
  });
  const baseUrl = `http://127.0.0.1:${server.port}/v1`;
  try {
    await expect(createAnthropicJudge({ apiKey: "test", baseUrl })("cat secrets.env")).resolves.toMatchObject({
      safe: false,
      reasoning: "Anthropic denied",
    });
    await expect(createOpenAIJudge({ apiKey: "test", baseUrl })("cat secrets.env")).resolves.toMatchObject({
      safe: false,
      reasoning: "OpenAI denied",
    });
  } finally {
    server.stop(true);
  }

  expect(requests).toEqual([
    expect.objectContaining({ path: "/v1/messages", body: expect.objectContaining({ model: "claude-haiku-4-5" }) }),
    expect.objectContaining({ path: "/v1/chat/completions", body: expect.objectContaining({ model: "gpt-4o-mini" }) }),
  ]);
});
