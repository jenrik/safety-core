import { afterEach, expect, test } from "bun:test";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createOpenCodePlugin } from "../adapters/opencode.ts";
import { createOpenCodeV2Plugin } from "../adapters/opencode-v2.ts";
import { ClientHelloSchema, ServerHelloSchema, ServerHello_Failure } from "../src/redact/gen/handshake_pb.ts";
import { RedactRequestSchema, RedactResponseSchema, RedactResponse_ErrorCode } from "../src/redact/gen/redact_v1_pb.ts";
import { redactOpenCodeToolResult } from "../src/redact/opencode.ts";
import type { LoadedPolicyRuntime } from "../src/index.ts";

const TOKEN = "ghp_" + "A".repeat(36);
const limits = { maxFunctionDepth: 8, maxNestedScriptDepth: 8, maxSteps: 100, maxWorkItems: 100 };
const directories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) await new Promise<void>((resolve) => server.close(() => resolve()));
  for (const directory of directories.splice(0)) rmSync(directory, { force: true, recursive: true });
});

function runtime(socketPath: string): LoadedPolicyRuntime {
  return { config: { bashAnalysis: limits, redact: { opencode: { enabled: true, socketPath } } }, policySet: { policies: [], sources: [] }, limits } as unknown as LoadedPolicyRuntime;
}

function frame(payload: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length);
  return Buffer.concat([header, payload]);
}

async function startServer(mode: "ok" | "unsupported" | "processing_failed" = "ok") {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-redact-wire-"));
  directories.push(directory);
  const path = join(directory, "redact.sock");
  let handshakes = 0;
  let requests = 0;
  const server = createServer((socket) => {
    let incoming = Buffer.alloc(0);
    let negotiated = false;
    socket.on("data", (chunk) => {
      incoming = Buffer.concat([incoming, chunk]);
      while (incoming.length >= 4 && incoming.length >= incoming.readUInt32BE(0) + 4) {
        const length = incoming.readUInt32BE(0);
        const payload = incoming.subarray(4, length + 4);
        incoming = incoming.subarray(length + 4);
        if (!negotiated) {
          const hello = fromBinary(ClientHelloSchema, payload);
          expect(hello.protocolId).toBe("safety-core-redact");
          expect(hello.supportedVersions).toEqual([1]);
          handshakes++;
          negotiated = true;
          socket.write(frame(toBinary(ServerHelloSchema, create(ServerHelloSchema, mode === "unsupported"
            ? { failure: ServerHello_Failure.NO_COMMON_VERSION }
            : { selectedVersion: 1 }))));
          if (mode === "unsupported") socket.end();
          continue;
        }
        const request = fromBinary(RedactRequestSchema, payload);
        requests++;
        const response = mode === "processing_failed"
          ? { result: { case: "error" as const, value: RedactResponse_ErrorCode.PROCESSING_FAILED } }
          : { result: { case: "text" as const, value: request.text!.replaceAll(TOKEN, "<REDACTED>") } };
        socket.write(frame(toBinary(RedactResponseSchema, create(RedactResponseSchema, response))));
      }
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(path, resolve));
  return { path, stats: () => ({ handshakes, requests }) };
}

test("both OpenCode adapters redact every text channel after one handshake per result", async () => {
  const socket = await startServer();
  for (const createPlugin of [createOpenCodePlugin, createOpenCodeV2Plugin]) {
    const plugin = await createPlugin({ runtime: runtime(socket.path) });
    for (const tool of ["bash", "read", "webfetch"]) {
      const output = {
        title: `title ${TOKEN}`,
        output: `output ${TOKEN}`,
        metadata: { nested: [TOKEN], safe: "keep", optional: undefined },
        attachments: [{ data: TOKEN }],
      };
      await plugin["tool.execute.after"]({ tool, args: tool === "bash" ? { command: "id" } : {} } as never, output);
      expect(output).toEqual({
        title: "title <REDACTED>", output: "output <REDACTED>",
        metadata: { nested: ["<REDACTED>"], safe: "keep" }, attachments: [],
      });
      expect(JSON.stringify(output)).not.toContain(TOKEN);
    }
  }
  expect(socket.stats()).toEqual({ handshakes: 6, requests: 18 });
});

test("unsupported handshake and processing failure withhold the whole result", async () => {
  for (const mode of ["unsupported", "processing_failed"] as const) {
    const socket = await startServer(mode);
    const plugin = await createOpenCodePlugin({ runtime: runtime(socket.path) });
    const output = { title: TOKEN, output: TOKEN, metadata: { nested: TOKEN }, attachments: [TOKEN] };
    await plugin["tool.execute.after"]({ tool: "read", args: {} } as never, output);
    expect(output).toEqual({
      title: "Tool result withheld", output: "[Tool result withheld: redaction unavailable]", metadata: {}, attachments: [],
    });
  }
});

test("missing socket withholds instead of throwing or returning raw output", async () => {
  const plugin = await createOpenCodeV2Plugin({ runtime: runtime("/tmp/nonexistent-safety-core-redact.sock") });
  const output = { title: TOKEN, output: TOKEN, metadata: TOKEN };
  await plugin["tool.execute.after"]({ tool: "bash", args: { command: "id" } } as never, output);
  expect(JSON.stringify(output)).not.toContain(TOKEN);
  expect(output.output).toContain("withheld");
});

test("binary or cyclic metadata cannot bypass text redaction", async () => {
  const config = { opencode: { enabled: true, socketPath: "/not-used" } };
  for (const metadata of [Buffer.from(TOKEN), new Uint8Array(Buffer.from(TOKEN)), (() => {
    const cyclic: { self?: unknown } = {};
    cyclic.self = cyclic;
    return cyclic;
  })()]) {
    const output = { title: "title", output: TOKEN, metadata };
    await redactOpenCodeToolResult(output, config, async () => ({ redact: async (text: string) => text, close: () => {} }));
    expect(output.title).toBe("Tool result withheld");
    expect(output.output).toContain("withheld");
    expect(output.metadata).toEqual({});
  }
});

test("property: arbitrary result fields are either sanitized or all withheld", async () => {
  const config = { opencode: { enabled: true, socketPath: "/not-used" } };
  for (let seed = 0; seed < 256; seed++) {
    const text = `message-${seed}-${TOKEN}`;
    const result = { title: text, output: text, metadata: { value: text } };
    let calls = 0;
    await redactOpenCodeToolResult(result, config, async () => ({
      redact: async (value: string) => {
        if (seed % 7 === 0 && ++calls === 2) throw new Error(`raw ${TOKEN}`);
        return value.replaceAll(TOKEN, "<REDACTED>");
      },
      close: () => {},
    }));
    expect(JSON.stringify(result), `seed ${seed}`).not.toContain(TOKEN);
    expect(result.output, `seed ${seed}`).toBe(seed % 7 === 0 ? "[Tool result withheld: redaction unavailable]" : `message-${seed}-<REDACTED>`);
  }
});
