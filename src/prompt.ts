import { randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { ClientHelloSchema, ServerHello_Failure, ServerHelloSchema } from "./prompt/gen/prompt_handshake_pb.js";
import { PermissionPromptRequestSchema, PermissionPromptResponseSchema } from "./prompt/gen/prompt_v1_pb.js";

/** Environment variable inherited by nested harness processes. */
export const SAFETY_CORE_PROMPT_SOCKET = "SAFETY_CORE_PROMPT_SOCKET";
/** Internal marker preventing the root process from connecting to itself. */
export const SAFETY_CORE_PROMPT_ROOT_PID = "SAFETY_CORE_PROMPT_ROOT_PID";

const VERSION = 1;
const PROTOCOL_ID = "safety-core-prompt";
const MAX_HANDSHAKE_BYTES = 4 * 1024;
const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_BUFFERED_BYTES = MAX_HANDSHAKE_BYTES + MAX_MESSAGE_BYTES + 8;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1_000;

export interface PermissionPromptRequest {
  readonly title: string;
  readonly message: string;
}

export interface PermissionPromptServer {
  /** Absolute path exported to child processes through SAFETY_CORE_PROMPT_SOCKET. */
  readonly path: string;
  close(): Promise<void>;
}

export interface PermissionPromptClientOptions {
  readonly socketPath?: string;
  readonly environment?: Readonly<Record<string, string | undefined>>;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

/**
 * Start a root-harness prompt endpoint. Each endpoint uses its own mode-0700
 * temporary directory so unrelated local users cannot replace the socket.
 */
export async function createPermissionPromptServer(
  prompt: (request: PermissionPromptRequest) => Promise<boolean>,
): Promise<PermissionPromptServer> {
  const directory = mkdtempSync(join(tmpdir(), "safety-core-prompt-"));
  chmodSync(directory, 0o700);
  const path = join(directory, "prompt.sock");
  const server = createServer();
  const sockets = new Set<Socket>();
  let queue = Promise.resolve();
  const cleanup = () => {
    server.close();
    rmSync(directory, { force: true, recursive: true });
  };

  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    void respondToPrompt(socket, (request) => {
      const result = queue.then(() => prompt(request)).catch(() => false);
      queue = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    });
  });

  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(path, () => {
        server.off("error", reject);
        // The extension must not keep a harness process alive after it exits.
        server.unref();
        resolve();
      });
    });
  } catch (error) {
    server.close();
    rmSync(directory, { force: true, recursive: true });
    throw error;
  }
  process.once("exit", cleanup);

  return Object.freeze({
    path,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      process.off("exit", cleanup);
      try {
        unlinkSync(path);
      } catch {}
      rmSync(directory, { force: true, recursive: true });
    },
  });
}

/**
 * Ask the inherited root harness for a decision. Undefined means no endpoint
 * is configured or reachable, allowing a harness to use its native fallback.
 */
export function forwardPermissionPrompt(
  request: PermissionPromptRequest,
  options: PermissionPromptClientOptions = {},
): Promise<boolean | undefined> {
  const environment = options.environment ?? process.env;
  const socketPath = options.socketPath ?? environment[SAFETY_CORE_PROMPT_SOCKET];
  if (typeof socketPath !== "string" || socketPath.length === 0) return Promise.resolve(undefined);
  const rootPID =
    options.environment === undefined && options.socketPath === undefined
      ? process.env[SAFETY_CORE_PROMPT_ROOT_PID]
      : options.environment?.[SAFETY_CORE_PROMPT_ROOT_PID];
  if (rootPID === String(process.pid)) return Promise.resolve(undefined);
  if (!isPromptRequest(request)) return Promise.resolve(false);
  if (options.signal?.aborted) return Promise.resolve(false);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return Promise.resolve(false);

  return new Promise<boolean | undefined>((resolve) => {
    const socket = createConnection({ path: socketPath });
    const reader = new FrameReader(socket);
    const deadline = setTimeout(() => finish(undefined), timeoutMs);
    let settled = false;
    const finish = (result: boolean | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket.destroy();
      options.signal?.removeEventListener("abort", abort);
      resolve(result);
    };
    const abort = () => finish(false);
    socket.on("error", () => {});
    options.signal?.addEventListener("abort", abort, { once: true });
    void (async () => {
      try {
        await waitForConnection(socket);
        socket.write(frame(toBinary(ClientHelloSchema, create(ClientHelloSchema, handshakeRequest()))));
        const hello = fromBinary(ServerHelloSchema, await reader.read(MAX_HANDSHAKE_BYTES));
        if (hello.selectedVersion !== VERSION || hello.failure !== ServerHello_Failure.FAILURE_UNSPECIFIED) {
          return finish(undefined);
        }
        const id = randomUUID();
        socket.write(
          frame(
            toBinary(
              PermissionPromptRequestSchema,
              create(PermissionPromptRequestSchema, { id, title: request.title, message: request.message }),
            ),
          ),
        );
        const response = fromBinary(PermissionPromptResponseSchema, await reader.read(MAX_MESSAGE_BYTES));
        finish(response.id === id ? response.approved : undefined);
      } catch {
        finish(undefined);
      }
    })();
  });
}

async function respondToPrompt(
  socket: Socket,
  prompt: (request: PermissionPromptRequest) => Promise<boolean>,
): Promise<void> {
  socket.on("error", () => {});
  socket.setTimeout(DEFAULT_TIMEOUT_MS, () => socket.destroy());
  try {
    const reader = new FrameReader(socket);
    const hello = fromBinary(ClientHelloSchema, await reader.read(MAX_HANDSHAKE_BYTES));
    const negotiated = hello.protocolId === PROTOCOL_ID && hello.supportedVersions.includes(VERSION);
    socket.write(
      frame(
        toBinary(
          ServerHelloSchema,
          create(ServerHelloSchema, {
            selectedVersion: negotiated ? VERSION : 0,
            failure: negotiated ? ServerHello_Failure.FAILURE_UNSPECIFIED : ServerHello_Failure.NO_COMMON_VERSION,
          }),
        ),
      ),
    );
    if (!negotiated) {
      socket.end();
      return;
    }
    const request = fromBinary(PermissionPromptRequestSchema, await reader.read(MAX_MESSAGE_BYTES));
    if (!isPromptRequest(request) || request.id.length === 0) {
      socket.destroy();
      return;
    }
    const approved = await prompt({ title: request.title, message: request.message });
    socket.end(
      frame(
        toBinary(PermissionPromptResponseSchema, create(PermissionPromptResponseSchema, { id: request.id, approved })),
      ),
    );
  } catch {
    socket.destroy();
  }
}

function handshakeRequest(): { protocolId: string; supportedVersions: number[] } {
  return { protocolId: PROTOCOL_ID, supportedVersions: [VERSION] };
}

function frame(bytes: Uint8Array): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.byteLength);
  return Buffer.concat([header, bytes]);
}

function isPromptRequest(value: PermissionPromptRequest): boolean {
  return (
    typeof value.title === "string" &&
    typeof value.message === "string" &&
    Buffer.byteLength(value.title) + Buffer.byteLength(value.message) <= MAX_MESSAGE_BYTES
  );
}

function waitForConnection(socket: Socket): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
}

/** Read fixed-size-prefixed protobuf messages without assuming socket chunk boundaries. */
class FrameReader {
  private readonly chunks: AsyncIterator<Buffer>;
  private pending = Buffer.alloc(0);

  constructor(socket: Socket) {
    this.chunks = socket[Symbol.asyncIterator]();
  }

  async read(limit: number): Promise<Buffer> {
    while (this.pending.length < 4) await this.readChunk();
    const length = this.pending.readUInt32BE(0);
    if (length > limit) throw new Error("prompt message exceeds its protocol limit");
    while (this.pending.length < length + 4) await this.readChunk();
    const body = this.pending.subarray(4, length + 4);
    this.pending = this.pending.subarray(length + 4);
    return body;
  }

  private async readChunk(): Promise<void> {
    const chunk = await this.chunks.next();
    if (chunk.done) throw new Error("prompt socket closed before a complete message arrived");
    this.pending = Buffer.concat([this.pending, Buffer.from(chunk.value)]);
    if (this.pending.length > MAX_BUFFERED_BYTES) throw new Error("prompt socket buffer limit exceeded");
  }
}
