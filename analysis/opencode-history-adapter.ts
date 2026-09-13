import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { initBashParser } from "../src/index.ts";

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
  /** Disabled by default so replay never sends historical commands to an LLM provider. */
  readonly allowJudge?: boolean;
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
  if (typeof event.command !== "string") throw new Error("Historical Bash event command must be a string");
  if (event.nativePermission && !["allow", "ask", "deny"].includes(event.nativePermission)) {
    throw new Error(`Invalid native Bash permission status: ${event.nativePermission}`);
  }

  // Source checkouts keep the grammar under node_modules; packaged adapters
  // keep it at their root. Initialize before importing the production plugin.
  const root = fileURLToPath(new URL("..", import.meta.url));
  const packagedGrammar = `${root}/tree-sitter-bash.wasm`;
  await initBashParser(
    root,
    existsSync(packagedGrammar) ? packagedGrammar : `${root}/node_modules/tree-sitter-bash/tree-sitter-bash.wasm`,
  );
  const plugin = await loadPlugin(event.allowJudge === true);
  const before = plugin["tool.execute.before"];
  const permission = plugin["permission.ask"];
  if (!before || !permission) throw new Error("OpenCode plugin did not register required Bash hooks");

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

async function loadPlugin(allowJudge: boolean): Promise<OpenCodePlugin> {
  if (allowJudge) return (await (await import("../adapters/opencode.ts")).default()) as OpenCodePlugin;

  const keys = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"] as const;
  const original = new Map(keys.map((key) => [key, process.env[key]]));
  try {
    for (const key of keys) delete process.env[key];
    return (await (await import("../adapters/opencode.ts")).default()) as OpenCodePlugin;
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
