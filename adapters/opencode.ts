// OpenCode Plugin adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between OpenCode's plugin API and core decision functions.

import type { Plugin, PluginInput } from "@opencode-ai/plugin";
import { createHash } from "node:crypto";
import { join } from "node:path";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  appendAuditRecord,
  checkWebfetchUrl,
  createBashProfileSnapshotSource,
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
  type BashProfileSnapshotSource,
  type BashProfileSnapshotVersion,
  type JudgeProvider,
} from "../src/index.js";

export interface OpenCodePluginDependencies {
  readonly evaluateConfiguredBash?: BashConfiguredEvaluator;
  readonly profileSnapshotSource?: BashProfileSnapshotSource;
}

export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const permissionEvaluator = dependencies.evaluateConfiguredBash ?? evaluateConfiguredBash;
  const profileSnapshots = dependencies.profileSnapshotSource ?? createBashProfileSnapshotSource();
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
      const snapshot = profileSnapshots.reloadIfChanged();
      const evaluation = await evaluateForOpenCode(command, permissionEvaluator, snapshot, client, () => bashResults.shouldNotifyAnalysisFailure(input, command, bashResults.sessionID(input)));
      const guardReason = openCodeBashGuardBlockReason(evaluation);
      if (guardReason) throw new Error(guardReason);

      // ── LLM Judge: second pass for secret-adjacent commands ──────────
      if (shouldInvokeJudge(command)) {
        const verdict = await invokeJudge(command);
        if (verdict && !verdict.safe) {
          throw new Error(`Blocked by OpenCode safety policy (🧑‍⚖️ judge): ${verdict.reasoning}`);
        }
      }
      bashResults.store(input, command, evaluation, snapshot.generation);
      bashResults.linkLegacyAnalysisFailure(input, command, bashResults.sessionID(input));
    },

    // Older OpenCode releases invoke permission.ask with the parsed command.
    // Current releases use permission.asked below; retain this compatibility
    // route while they transition their plugin API.
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;

      const command = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!command) return;
      // Permission callbacks must observe their own event-local config snapshot.
      const decision = (await evaluateForOpenCode(
        command,
        permissionEvaluator,
        profileSnapshots.reloadIfChanged(),
        client,
        () => bashResults.shouldNotifyAnalysisFailure(bashResults.permissionIdentity(input), command, bashResults.sessionID(input)),
      )).permission;
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
      const identity = bashResults.permissionIdentity(event.properties);
      const cached = bashResults.lookup(identity, command);
      if (cached.key) bashResults.bindRequest(event.properties.id, cached.key);
      const snapshot = profileSnapshots.reloadIfChanged();
      const decision = cached.evaluation && cached.generation === snapshot.generation
        ? cached.evaluation.permission
        : (await evaluateForOpenCode(command, permissionEvaluator, snapshot, client, () => bashResults.shouldNotifyAnalysisFailure(identity, command, bashResults.sessionID(event.properties)))).permission;
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
      const evaluation = cached ?? await evaluateForOpenCode(command, permissionEvaluator, profileSnapshots.reloadIfChanged(), client, () => bashResults.shouldNotifyAnalysisFailure(input, command, bashResults.sessionID(input)));
      const summary = kubectlSecretAudit(evaluation.audit.events);
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

function evaluateConfigured(command: string, evaluate: BashConfiguredEvaluator, version: BashProfileSnapshotVersion): BashConfiguredEvaluation {
  return evaluate({ source: command, initialEnvironment: { kind: "unavailable" }, profileSnapshot: version.snapshot });
}

async function evaluateForOpenCode(
  command: string,
  evaluate: BashConfiguredEvaluator,
  version: BashProfileSnapshotVersion,
  client: PluginInput["client"] | undefined,
  shouldNotify: () => boolean = () => true,
): Promise<BashConfiguredEvaluation> {
  try {
    const evaluation = evaluateConfigured(command, evaluate, version);
    if (evaluation.analysis.failure && shouldNotify()) {
      await showAnalysisNotification(client, evaluation.analysis.failure.budget
        ? "Safety analysis reached its complexity limit. OpenCode will use its normal permission policy."
        : "Safety analysis could not be completed. OpenCode will use its normal permission policy.");
    }
    return evaluation;
  } catch (error) {
    if (shouldNotify()) {
      await showAnalysisNotification(client, "Safety analysis could not be completed. OpenCode will use its normal permission policy.");
    }
    throw error;
  }
}

/** Notifications are advisory; inability to display one must not alter permission handling. */
async function showAnalysisNotification(client: PluginInput["client"] | undefined, message: string): Promise<void> {
  if (!client) return;
  try {
    await client.tui.showToast({
      body: { title: "Safety analysis incomplete", message, variant: "warning" },
    });
  } catch {
    // A notification failure must not change the permission result.
  }
}

function kubectlSecretAudit(events: BashConfiguredEvaluation["audit"]["events"]): BashConfiguredEvaluation["audit"]["events"][number]["fields"] | null {
  return events.find((event) => event.kind === "kubectl-secret")?.fields ?? null;
}

function defaultAuditPath(agent: string): string {
  return join(process.env.XDG_STATE_HOME ?? join(process.env.HOME ?? "", ".local", "state"), agent, "kubectl-secret-audit.jsonl");
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
  readonly generation: number;
}

interface CachedLookup {
  readonly key: string | null;
  readonly evaluation: BashConfiguredEvaluation | null;
  readonly generation: number | null;
}

const BASH_RESULT_TTL_MS = 10 * 60 * 1_000;
const MAX_CACHED_BASH_RESULTS = 128;

/** Event IDs, not command text, establish the only cross-callback reuse boundary. */
function createBashResultCache() {
  const entries = new Map<string, CachedBashEvaluation>();
  const requests = new Map<string, string>();
  const notifiedFailures = new Map<string, FailureNotification>();
  const legacyFailureNotifications = new Map<string, FailureNotification[]>();

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

  function sessionID(value: unknown): string | null {
    return isRecord(value) && typeof value.sessionID === "string" && value.sessionID.length > 0
      ? value.sessionID
      : null;
  }

  function lookup(value: BashLifecycleInput | null, source: string): CachedLookup {
    prune();
    const resultKey = value ? key(value) : null;
    if (!resultKey) return { key: null, evaluation: null, generation: null };
    const entry = entries.get(resultKey);
    if (!entry || entry.source !== source) {
      if (entry) drop(resultKey);
      return { key: null, evaluation: null, generation: null };
    }
    return { key: resultKey, evaluation: entry.evaluation, generation: entry.generation };
  }

  function store(value: BashLifecycleInput, source: string, evaluation: BashConfiguredEvaluation, generation: number): void {
    const resultKey = key(value);
    if (!resultKey) return;
    prune();
    entries.delete(resultKey);
    entries.set(resultKey, { source, evaluation, createdAt: Date.now(), generation });
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
    for (const [resultKey, notification] of notifiedFailures) {
      if (resultKey.startsWith(`${sessionID}\u0000`)) dropFailureNotification(notification);
    }
  }

  function shouldNotifyAnalysisFailure(
    value: BashLifecycleInput | null,
    source: string,
    sessionID: string | null,
  ): boolean {
    prune();
    const resultKey = value ? key(value) : null;
    // Older permission.ask events may not carry lifecycle IDs. Retain only a
    // digest so their paired before hook cannot produce a second toast.
    const legacyKey = `legacy:${sessionID ?? ""}:${createHash("sha256").update(source).digest("base64url")}`;
    if (!resultKey) return consumeLegacyFailureNotification(legacyKey);
    if (notifiedFailures.has(resultKey)) return false;
    const notification: FailureNotification = Object.freeze({ resultKey, legacyKey, createdAt: Date.now() });
    notifiedFailures.set(resultKey, notification);
    while (notifiedFailures.size > MAX_CACHED_BASH_RESULTS) dropFailureNotification(notifiedFailures.values().next().value!);
    return true;
  }

  /** Pair a successful before hook with the legacy permission callback. */
  function linkLegacyAnalysisFailure(value: BashLifecycleInput, source: string, sessionID: string | null): void {
    const resultKey = key(value);
    if (!resultKey) return;
    const notification = notifiedFailures.get(resultKey);
    if (!notification) return;
    const legacyKey = `legacy:${sessionID ?? ""}:${createHash("sha256").update(source).digest("base64url")}`;
    if (notification.legacyKey !== legacyKey) return;
    const legacy = legacyFailureNotifications.get(legacyKey) ?? [];
    if (!legacy.includes(notification)) legacy.push(notification);
    legacyFailureNotifications.set(legacyKey, legacy);
  }

  function consumeLegacyFailureNotification(legacyKey: string): boolean {
    const notifications = legacyFailureNotifications.get(legacyKey);
    const notification = notifications?.shift();
    if (!notifications || notifications.length === 0) legacyFailureNotifications.delete(legacyKey);
    return !notification;
  }

  function dropFailureNotification(notification: FailureNotification): void {
    if (notifiedFailures.get(notification.resultKey) === notification) notifiedFailures.delete(notification.resultKey);
    const legacy = legacyFailureNotifications.get(notification.legacyKey);
    if (!legacy) return;
    const index = legacy.indexOf(notification);
    if (index >= 0) legacy.splice(index, 1);
    if (legacy.length === 0) legacyFailureNotifications.delete(notification.legacyKey);
  }

  function drop(resultKey: string): void {
    entries.delete(resultKey);
    const notification = notifiedFailures.get(resultKey);
    if (notification) dropFailureNotification(notification);
    for (const [requestID, mapped] of requests) if (mapped === resultKey) requests.delete(requestID);
  }

  function prune(): void {
    const cutoff = Date.now() - BASH_RESULT_TTL_MS;
    for (const [resultKey, entry] of entries) if (entry.createdAt < cutoff) drop(resultKey);
    for (const notification of new Set(notifiedFailures.values())) {
      if (notification.createdAt < cutoff) dropFailureNotification(notification);
    }
  }

  return Object.freeze({ identity, permissionIdentity, sessionID, lookup, store, take, bindRequest, dropRequest, dropSession, shouldNotifyAnalysisFailure, linkLegacyAnalysisFailure });
}

interface FailureNotification {
  readonly resultKey: string;
  readonly legacyKey: string;
  readonly createdAt: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
