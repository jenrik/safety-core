import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { initBashParser, setJudgeProvider, unavailableExecutableFilesystem } from "../src/index.ts";

/**
 * Replay recorded OpenCode Bash calls through the production plugin hooks.
 *
 * The adapter deliberately never executes a command. It supplies the same
 * hook inputs that OpenCode supplies before execution and at its permission
 * gate, making it suitable for offline history analysis and manual fixtures.
 */
export interface HistoricalBashEvent {
  readonly command: string;
  readonly nativePermission?: "allow" | "ask" | "deny";
}

export interface HistoricalBashPolicyResult {
  readonly command: string;
  readonly policyDecision: "allow" | "ask" | "deny";
  readonly policyAllowed: boolean;
  readonly policyDenied: boolean;
  readonly reason: string | null;
}

type OpenCodePlugin = Record<string, (input: Record<string, unknown>, output: Record<string, unknown>) => Promise<void>>;

export async function replayHistoricalBashEvent(event: HistoricalBashEvent): Promise<HistoricalBashPolicyResult> {
  const [result] = await replayHistoricalBashEvents([event]);
  return result!;
}

/** Replay an offline event batch using one initialized production plugin. */
export async function replayHistoricalBashEvents(
  events: readonly HistoricalBashEvent[],
): Promise<readonly HistoricalBashPolicyResult[]> {
  if (events.length === 0) return Object.freeze([]);
  for (const event of events) validateEvent(event);

  // Source checkouts keep the grammar under node_modules; packaged adapters
  // keep it at their root. Initialize before importing the production plugin.
  const root = fileURLToPath(new URL("..", import.meta.url));
  const packagedGrammar = `${root}/tree-sitter-bash.wasm`;
  await initBashParser(
    root,
    existsSync(packagedGrammar) ? packagedGrammar : `${root}/node_modules/tree-sitter-bash/tree-sitter-bash.wasm`,
  );
  const plugin = await loadPlugin();
  const before = plugin["tool.execute.before"];
  const permission = plugin["permission.ask"];
  if (!before || !permission) throw new Error("OpenCode plugin did not register required Bash hooks");

  const results: HistoricalBashPolicyResult[] = [];
  for (const event of events) results.push(await replayWithPlugin(event, before, permission));
  return Object.freeze(results);
}

async function replayWithPlugin(
  event: HistoricalBashEvent,
  before: OpenCodePlugin["tool.execute.before"],
  permission: OpenCodePlugin["permission.ask"],
): Promise<HistoricalBashPolicyResult> {
  // The production plugin shares this provider at module scope. Clear it for
  // every event so a concurrently loaded plugin cannot enable live judging.
  setJudgeProvider(null);
  try {
    await before({ tool: "bash" }, { args: { command: event.command } });
  } catch (error) {
    return result(event.command, "deny", errorMessage(error));
  }

  const output: Record<string, unknown> = { status: event.nativePermission ?? "ask" };
  await permission({ type: "bash", pattern: event.command }, output);
  const policyDecision = output.status;
  if (policyDecision !== "allow" && policyDecision !== "ask" && policyDecision !== "deny") {
    throw new Error(`OpenCode plugin returned an invalid Bash permission status: ${String(policyDecision)}`);
  }
  return result(event.command, policyDecision, null);
}

function validateEvent(event: HistoricalBashEvent): void {
  if (!event || typeof event.command !== "string") throw new Error("Historical Bash event command must be a string");
  if (event.nativePermission && !["allow", "ask", "deny"].includes(event.nativePermission)) {
    throw new Error(`Invalid native Bash permission status: ${event.nativePermission}`);
  }
}

async function loadPlugin(): Promise<OpenCodePlugin> {
  const keys = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"] as const;
  const original = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    for (const key of keys) delete process.env[key];
    const plugin = await (await import("../adapters/opencode.ts")).createOpenCodePlugin({ executableFilesystem: unavailableExecutableFilesystem }) as OpenCodePlugin;
    setJudgeProvider(null);
    return plugin;
  } finally {
    for (const key of keys) {
      const value = original.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function result(
  command: string,
  policyDecision: HistoricalBashPolicyResult["policyDecision"],
  reason: string | null,
): HistoricalBashPolicyResult {
  return Object.freeze({
    command,
    policyDecision,
    policyAllowed: policyDecision === "allow",
    policyDenied: policyDecision === "deny",
    reason,
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
