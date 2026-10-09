import { expect, test } from "bun:test";
import { createPermissionPromptServer, forwardPermissionPrompt, SAFETY_CORE_PROMPT_SOCKET } from "../src/index.ts";

test("permission prompt server forwards an exact request and decision over its Unix socket", async () => {
  const requests: Array<{ title: string; message: string }> = [];
  const server = await createPermissionPromptServer(async (request) => {
    requests.push(request);
    return true;
  });
  try {
    await expect(
      forwardPermissionPrompt(
        { title: "Safety permission required", message: "nested command\nAllow it once?" },
        { socketPath: server.path },
      ),
    ).resolves.toBe(true);
    expect(requests).toEqual([{ title: "Safety permission required", message: "nested command\nAllow it once?" }]);
  } finally {
    await server.close();
  }
});

test("permission prompt forwarding falls back only when no root endpoint is available", async () => {
  await expect(
    forwardPermissionPrompt({ title: "title", message: "message" }, { environment: {} }),
  ).resolves.toBeUndefined();
  await expect(
    forwardPermissionPrompt(
      { title: "title", message: "message" },
      { environment: { [SAFETY_CORE_PROMPT_SOCKET]: "/tmp/safety-core-no-such-prompt.sock" }, timeoutMs: 100 },
    ),
  ).resolves.toBeUndefined();
});

test("property: prompt protocol preserves each generated request and its decision across 1,024 calls", async () => {
  const received: Array<{ title: string; message: string }> = [];
  const server = await createPermissionPromptServer(async (request) => {
    received.push(request);
    return (request.title.length + request.message.length) % 2 === 0;
  });
  try {
    for (let seed = 0; seed < 1_024; seed++) {
      const request = {
        title: `Nested harness ${seed}`,
        message: `permission ${"x".repeat(seed % 73)}\ncommand-${seed}`,
      };
      expect(await forwardPermissionPrompt(request, { socketPath: server.path }), `seed ${seed}`).toBe(
        (request.title.length + request.message.length) % 2 === 0,
      );
    }
    expect(received).toHaveLength(1_024);
    for (let seed = 0; seed < received.length; seed++) {
      expect(received[seed], `seed ${seed}`).toEqual({
        title: `Nested harness ${seed}`,
        message: `permission ${"x".repeat(seed % 73)}\ncommand-${seed}`,
      });
    }
  } finally {
    await server.close();
  }
});
