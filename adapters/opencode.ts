// OpenCode Plugin adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between OpenCode's plugin API and core decision functions.

import type { Plugin, PluginInput } from "@opencode-ai/plugin";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  appendAuditRecord,
  checkWebfetchUrl,
  defaultAuditPath,
  discoverWasmDir,
  evaluateConfiguredBash,
  initBashParser,
  isSecretPath,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type BashConfiguredEvaluation,
  type BashConfiguredOptions,
  type JudgeProvider,
} from "../src/index.js";

export interface OpenCodePluginDependencies {
  readonly evaluateConfiguredBash?: BashConfiguredEvaluator;
}

export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const permissionEvaluator = dependencies.evaluateConfiguredBash ?? evaluateConfiguredBash;
  const bashResults = createBashResultCache();

  // TODO: Integrate with OpenCode's native model runtime so the judge can use
  // every configured provider instead of selecting raw Anthropic/OpenAI keys.
  // OpenCode sets ANTHROPIC_API_KEY / OPENAI_API_KEY from its provider config.
  setJudgeProvider(buildJudgeProvider());

  return {
    "tool.execute.before": async (input, output) => {
      const args = output.args as Record<string, unknown>;

      if (input.tool === "read") {
        const path = String(args.filePath ?? args.file_path ?? args.path ?? "");
        if (isSecretPath(path)) {
          throw new Error(`Blocked by secrets policy: ${SECRET_BLOCK_MESSAGE}`);
        }
      }

      if (input.tool === "webfetch") {
        const reason = checkWebfetchUrl(String(args.url ?? ""));
        if (reason) throw new Error(reason);
      }

      if (input.tool !== "bash") return;
      const command = String(args.command ?? "");

      // ── Rule-based checks: hard-block clear violations ────────────
      const evaluation = evaluateConfigured(command, permissionEvaluator);
      const guardReason = openCodeBashGuardBlockReason(evaluation);
      if (guardReason) throw new Error(guardReason);

      // ── LLM Judge: second pass for secret-adjacent commands ──────────
      if (shouldInvokeJudge(command)) {
        const verdict = await invokeJudge(command);
        if (verdict && !verdict.safe) {
          throw new Error(`Blocked by OpenCode safety policy (🧑‍⚖️ judge): ${verdict.reasoning}`);
        }
      }
      bashResults.store(input, command, evaluation);
    },

    // Older OpenCode releases invoke permission.ask with the parsed command.
    // Current releases use permission.asked below; retain this compatibility
    // route while they transition their plugin API.
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;

      const command = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!command) return;
      // Permission callbacks must observe their own event-local config snapshot.
      const decision = evaluateConfigured(command, permissionEvaluator).permission;
      if (decision.kind === "allow" || decision.kind === "deny") output.status = decision.kind;
    },

    // Current OpenCode versions publish this event instead of invoking
    // permission.ask. Replying once resolves the pending native request.
    event: async ({ event }) => {
      const properties = event.properties as Record<string, unknown>;
      if (event.type === "permission.replied" && (properties.reply === "reject" || properties.response === "reject")) {
        bashResults.dropRequest(properties.requestID ?? properties.permissionID);
        return;
      }
      if (event.type === "session.deleted") {
        bashResults.dropSession(properties.sessionID);
        return;
      }
      if (!client || event.type !== "permission.asked" || event.properties.permission !== "bash") return;
      const command = event.properties.patterns.join(" && ");
      const cached = bashResults.lookup(bashResults.permissionIdentity(event.properties), command);
      if (cached.key) bashResults.bindRequest(event.properties.id, cached.key);
      // Do not reuse a before-hook decision across a profile configuration change.
      const decision = evaluateConfigured(command, permissionEvaluator).permission;
      if (decision.kind === "allow") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "once" });
      } else if (decision.kind === "deny") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "reject", message: decision.reason });
      }
    },

    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash") return;
      const command = String((input.args as Record<string, unknown>).command ?? "");

      const cached = bashResults.take(input, command);
      const summary = (cached ?? evaluateConfigured(command, permissionEvaluator)).audit.kubectlSecret;
      if (summary) {
        await appendAuditRecord(defaultAuditPath("opencode"), {
          timestamp: new Date().toISOString(),
          ...summary,
        }).catch(() => {});
      }

      if (matchesSecretKeyword(command)) {
        output.output += `\n\n${SECRET_COMMAND_REMINDER}`;
      }
    },
  } satisfies Plugin;
}

export default async (input?: PluginInput) => createOpenCodePlugin({}, input?.client, input?.directory);

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a JudgeProvider from OpenCode's own provider configuration.
 *
 * Uses the harness's existing API keys (set by OpenCode from its config)
 * to decide which API to call.  No separate env-var config needed.
 */
function buildJudgeProvider(): JudgeProvider | null {
  if (process.env.ANTHROPIC_API_KEY) {
    return createAnthropicJudge({ apiKey: process.env.ANTHROPIC_API_KEY });
  }

  if (process.env.OPENAI_API_KEY) {
    return createOpenAIJudge({ apiKey: process.env.OPENAI_API_KEY });
  }

  return null;
}

function matchesSecretKeyword(command: string): boolean {
  const haystack = command.toLowerCase();
  return SECRET_PATTERNS.some((p) =>
    haystack.includes(p.toLowerCase().replaceAll("*", "")),
  );
}

type BashConfiguredEvaluator = (options: BashConfiguredOptions) => BashConfiguredEvaluation;

function evaluateConfigured(command: string, evaluate: BashConfiguredEvaluator): BashConfiguredEvaluation {
  return evaluate({ source: command, initialEnvironment: { kind: "unavailable" } });
}

/** Map one deny-only core guard evaluation to OpenCode's existing messages. */
export function openCodeBashGuardBlockReason(
  evaluation: BashConfiguredEvaluation,
): string | null {
  if (evaluation.guards.kind === "pass") return null;
  return evaluation.guards.policy.name === "github-http"
    ? evaluation.guards.reason
    : `Blocked by OpenCode safety policy: ${evaluation.guards.reason}`;
}

interface BashLifecycleInput {
  readonly sessionID?: unknown;
  readonly callID?: unknown;
}

interface CachedBashEvaluation {
  readonly source: string;
  readonly evaluation: BashConfiguredEvaluation;
  readonly createdAt: number;
}

interface CachedLookup {
  readonly key: string | null;
  readonly evaluation: BashConfiguredEvaluation | null;
}

const BASH_RESULT_TTL_MS = 10 * 60 * 1_000;
const MAX_CACHED_BASH_RESULTS = 128;

/** Event IDs, not command text, establish the only cross-callback reuse boundary. */
function createBashResultCache() {
  const entries = new Map<string, CachedBashEvaluation>();
  const requests = new Map<string, string>();

  function key(value: BashLifecycleInput): string | null {
    return typeof value.sessionID === "string" && value.sessionID.length > 0
      && typeof value.callID === "string" && value.callID.length > 0
      ? `${value.sessionID}\u0000${value.callID}`
      : null;
  }

  function identity(value: BashLifecycleInput): BashLifecycleInput | null {
    return key(value) ? value : null;
  }

  function permissionIdentity(value: unknown): BashLifecycleInput | null {
    if (!isRecord(value)) return null;
    const direct = identity({ sessionID: value.sessionID, callID: value.callID });
    if (direct || !isRecord(value.tool)) return direct;
    return identity({ sessionID: value.sessionID, callID: value.tool.callID });
  }

  function lookup(value: BashLifecycleInput | null, source: string): CachedLookup {
    prune();
    const resultKey = value ? key(value) : null;
    if (!resultKey) return { key: null, evaluation: null };
    const entry = entries.get(resultKey);
    if (!entry || entry.source !== source) {
      if (entry) drop(resultKey);
      return { key: null, evaluation: null };
    }
    return { key: resultKey, evaluation: entry.evaluation };
  }

  function store(value: BashLifecycleInput, source: string, evaluation: BashConfiguredEvaluation): void {
    const resultKey = key(value);
    if (!resultKey) return;
    prune();
    entries.delete(resultKey);
    entries.set(resultKey, { source, evaluation, createdAt: Date.now() });
    while (entries.size > MAX_CACHED_BASH_RESULTS) drop(entries.keys().next().value!);
  }

  function take(value: BashLifecycleInput, source: string): BashConfiguredEvaluation | null {
    const found = lookup(value, source);
    if (!found.key || !found.evaluation) return null;
    drop(found.key);
    return found.evaluation;
  }

  function bindRequest(requestID: unknown, resultKey: string): void {
    if (typeof requestID === "string" && requestID.length > 0) requests.set(requestID, resultKey);
  }

  function dropRequest(requestID: unknown): void {
    if (typeof requestID !== "string") return;
    const resultKey = requests.get(requestID);
    if (resultKey) drop(resultKey);
  }

  function dropSession(sessionID: unknown): void {
    if (typeof sessionID !== "string") return;
    for (const resultKey of entries.keys()) if (resultKey.startsWith(`${sessionID}\u0000`)) drop(resultKey);
  }

  function drop(resultKey: string): void {
    entries.delete(resultKey);
    for (const [requestID, mapped] of requests) if (mapped === resultKey) requests.delete(requestID);
  }

  function prune(): void {
    const cutoff = Date.now() - BASH_RESULT_TTL_MS;
    for (const [resultKey, entry] of entries) if (entry.createdAt < cutoff) drop(resultKey);
  }

  return Object.freeze({ identity, permissionIdentity, lookup, store, take, bindRequest, dropRequest, dropSession });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
