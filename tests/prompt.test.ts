import { expect, test } from "bun:test";
import { createConnection, type Socket } from "node:net";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createPermissionPromptServer, forwardPermissionPrompt, SAFETY_CORE_PROMPT_SOCKET } from "../src/index.ts";
import { ClientHelloSchema, ServerHello_Failure, ServerHelloSchema } from "../src/prompt/gen/prompt_handshake_pb.ts";

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

test("permission prompt server rejects an incompatible protobuf handshake before invoking the TUI", async () => {
  let prompts = 0;
  const server = await createPermissionPromptServer(async () => {
    prompts++;
    return true;
  });
  try {
    const socket = createConnection({ path: server.path });
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    socket.write(
      frame(toBinary(ClientHelloSchema, create(ClientHelloSchema, { protocolId: "wrong", supportedVersions: [1] }))),
    );
    const hello = fromBinary(ServerHelloSchema, await readFrame(socket));
    expect(hello.selectedVersion).toBe(0);
    expect(hello.failure).toBe(ServerHello_Failure.NO_COMMON_VERSION);
    expect(prompts).toBe(0);
    socket.destroy();
  } finally {
    await server.close();
  }
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

function frame(bytes: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([header, bytes]);
}

async function readFrame(socket: Socket): Promise<Buffer> {
  let pending = Buffer.alloc(0);
  for await (const chunk of socket) {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length < 4) continue;
    const length = pending.readUInt32BE(0);
    if (pending.length >= length + 4) return pending.subarray(4, length + 4);
  }
  throw new Error("prompt server closed before responding");
}
