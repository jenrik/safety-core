import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createConnection, type Socket } from "node:net";

import { ClientHelloSchema, ServerHelloSchema, ServerHello_Failure } from "./gen/handshake_pb.js";
import { RedactRequestSchema, RedactResponseSchema } from "./gen/redact_v1_pb.js";
import type { RedactConfig } from "../policy/config.js";

const VERSION = 1;
const PROTOCOL_ID = "safety-core-redact";
const MAX_HANDSHAKE_BYTES = 4096;
const MAX_MESSAGE_BYTES = 1024 * 1024;
const TIMEOUT_MS = 5000;
const WITHHELD = "[Tool result withheld: redaction unavailable]";

function frame(bytes: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([header, bytes]);
}

/** One connection negotiates once, then carries any number of v1 requests. */
export class RedactClient {
  private readonly chunks: AsyncIterator<Buffer>;
  private pending = Buffer.alloc(0);

  private constructor(private readonly socket: Socket, private readonly deadline: ReturnType<typeof setTimeout>) {
    this.chunks = socket[Symbol.asyncIterator]();
  }

  static async connect(path: string): Promise<RedactClient> {
    const socket = createConnection({ path });
    const deadline = setTimeout(() => socket.destroy(), TIMEOUT_MS);
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });
      const client = new RedactClient(socket, deadline);
      socket.write(frame(toBinary(ClientHelloSchema, create(ClientHelloSchema, { protocolId: PROTOCOL_ID, supportedVersions: [VERSION] }))));
      const hello = fromBinary(ServerHelloSchema, await client.read(MAX_HANDSHAKE_BYTES));
      if (hello.failure !== ServerHello_Failure.FAILURE_UNSPECIFIED || hello.selectedVersion !== VERSION) {
        throw new Error("redaction protocol negotiation failed");
      }
      return client;
    } catch {
      clearTimeout(deadline);
      socket.destroy();
      throw new Error("redaction service unavailable");
    }
  }

  async redact(text: string): Promise<string> {
    const request = toBinary(RedactRequestSchema, create(RedactRequestSchema, { text }));
    if (request.byteLength > MAX_MESSAGE_BYTES) throw new Error("redaction request too large");
    this.socket.write(frame(request));
    const response = fromBinary(RedactResponseSchema, await this.read(MAX_MESSAGE_BYTES));
    if (response.result.case !== "text") throw new Error("redaction service rejected result");
    return response.result.value;
  }

  close(): void {
    clearTimeout(this.deadline);
    this.socket.destroy();
  }

  private async read(limit: number): Promise<Buffer> {
    while (this.pending.length < 4) await this.readChunk(limit);
    const length = this.pending.readUInt32BE(0);
    if (length > limit) throw new Error("redaction response too large");
    while (this.pending.length < length + 4) await this.readChunk(limit);
    const body = this.pending.subarray(4, length + 4);
    this.pending = this.pending.subarray(length + 4);
    return body;
  }

  private async readChunk(limit: number): Promise<void> {
    const chunk = await this.chunks.next();
    if (chunk.done) throw new Error("redaction service closed the socket");
    this.pending = Buffer.concat([this.pending, Buffer.from(chunk.value)]);
    if (this.pending.length > limit + 4) throw new Error("redaction response too large");
  }
}

interface ToolResult {
  title: string;
  output: string;
  metadata: unknown;
  attachments?: unknown;
}

function serializeMetadata(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  const visited = new WeakSet<object>();
  let nodes = 0;
  function check(node: unknown, depth: number): void {
    if (++nodes > 10_000 || depth > 32) throw new Error("unsupported tool metadata");
    if (node === null || node === undefined || typeof node === "string" || typeof node === "boolean") return;
    if (typeof node === "number" && Number.isFinite(node)) return;
    if (typeof node !== "object" || visited.has(node)) throw new Error("unsupported tool metadata");
    if (!Array.isArray(node) && ![Object.prototype, null].includes(Object.getPrototypeOf(node))) {
      throw new Error("unsupported tool metadata");
    }
    visited.add(node);
    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(node))) {
      if (!("value" in descriptor)) throw new Error("unsupported tool metadata");
      check(descriptor.value, depth + 1);
    }
    visited.delete(node);
  }
  check(value, 0);
  return JSON.stringify(value);
}

/** Mutate every model-visible text channel, or replace the entire result. */
export async function redactOpenCodeToolResult(
  output: ToolResult,
  config: RedactConfig | undefined,
  connect: (path: string) => Promise<Pick<RedactClient, "redact" | "close">> = RedactClient.connect,
): Promise<void> {
  if (!config?.opencode.enabled) return;
  let client: Pick<RedactClient, "redact" | "close"> | undefined;
  try {
    const path = config.opencode.socketPath;
    if (!path || typeof output.title !== "string" || typeof output.output !== "string") throw new Error("invalid redaction input");
    client = await connect(path);
    const title = await client.redact(output.title);
    const body = await client.redact(output.output);
    const metadataJson = serializeMetadata(output.metadata);
    const metadata = metadataJson === undefined ? undefined : JSON.parse(await client.redact(metadataJson));
    output.title = title;
    output.output = body;
    output.metadata = metadata;
    // Binary attachments are not representable in this text-only first slice.
    if ("attachments" in output) output.attachments = [];
  } catch {
    // An after-hook exception might be translated by the harness into an error
    // containing the raw tool result. Replace it in place instead.
    output.title = "Tool result withheld";
    output.output = WITHHELD;
    output.metadata = {};
    if ("attachments" in output) output.attachments = [];
  } finally {
    client?.close();
  }
}
