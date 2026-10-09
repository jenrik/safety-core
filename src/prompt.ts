import { randomUUID } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { createServer, Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Environment variable inherited by nested harness processes. */
export const SAFETY_CORE_PROMPT_SOCKET = "SAFETY_CORE_PROMPT_SOCKET";
/** Internal marker preventing the root process from connecting to itself. */
export const SAFETY_CORE_PROMPT_ROOT_PID = "SAFETY_CORE_PROMPT_ROOT_PID";

const PROTOCOL_VERSION = 1;
const MAX_MESSAGE_BYTES = 64 * 1024;
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
    const id = randomUUID();
    const socket = new Socket();
    let settled = false;
    let received = "";
    const finish = (result: boolean | undefined) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      options.signal?.removeEventListener("abort", abort);
      resolve(result);
    };
    const abort = () => finish(false);
    options.signal?.addEventListener("abort", abort, { once: true });
    socket.setTimeout(timeoutMs, () => finish(undefined));
    socket.once("error", () => finish(undefined));
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("utf8");
      if (Buffer.byteLength(received) > MAX_MESSAGE_BYTES) return finish(undefined);
      const newline = received.indexOf("\n");
      if (newline === -1) return;
      const response = parseResponse(received.slice(0, newline));
      finish(response?.id === id ? response.approved : undefined);
    });
    socket.once("end", () => finish(undefined));
    socket.connect(socketPath, () => {
      socket.write(`${JSON.stringify({ version: PROTOCOL_VERSION, type: "permission-request", id, ...request })}\n`);
    });
  });
}

async function respondToPrompt(
  socket: Socket,
  prompt: (request: PermissionPromptRequest) => Promise<boolean>,
): Promise<void> {
  let received = "";
  socket.on("error", () => {});
  socket.on("data", async (chunk: Buffer) => {
    received += chunk.toString("utf8");
    if (Buffer.byteLength(received) > MAX_MESSAGE_BYTES) return socket.destroy();
    const newline = received.indexOf("\n");
    if (newline === -1) return;
    socket.pause();
    const request = parseRequest(received.slice(0, newline));
    const approved = request === undefined ? false : await prompt({ title: request.title, message: request.message });
    if (!socket.destroyed)
      socket.end(
        `${JSON.stringify({ version: PROTOCOL_VERSION, type: "permission-response", id: request?.id ?? "", approved })}\n`,
      );
  });
}

function parseRequest(value: string): ({ readonly id: string } & PermissionPromptRequest) | undefined {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (
      parsed.version !== PROTOCOL_VERSION ||
      parsed.type !== "permission-request" ||
      typeof parsed.id !== "string" ||
      parsed.id.length === 0 ||
      !isPromptRequest(parsed)
    )
      return undefined;
    return { id: parsed.id, title: parsed.title, message: parsed.message };
  } catch {
    return undefined;
  }
}

function parseResponse(value: string): { readonly id: string; readonly approved: boolean } | undefined {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    if (
      parsed.version !== PROTOCOL_VERSION ||
      parsed.type !== "permission-response" ||
      typeof parsed.id !== "string" ||
      typeof parsed.approved !== "boolean"
    )
      return undefined;
    return { id: parsed.id, approved: parsed.approved };
  } catch {
    return undefined;
  }
}

function isPromptRequest(value: unknown): value is PermissionPromptRequest {
  if (typeof value !== "object" || value === null) return false;
  const request = value as Record<string, unknown>;
  return (
    typeof request.title === "string" &&
    typeof request.message === "string" &&
    Buffer.byteLength(request.title) + Buffer.byteLength(request.message) <= MAX_MESSAGE_BYTES
  );
}
