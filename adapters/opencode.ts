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
  evaluateBashGuards,
  initBashParser,
  loadBashAnalysisLimits,
  loadGhPrCreatePolicy,
  isSecretPath,
  summariseKubectlSecret,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type BashAuthorizationContext,
  type BashConfiguredEvaluation,
  type BashConfiguredOptions,
  type BashGuardEvaluation,
  type BashGuardOptions,
  type JudgeProvider,
} from "../src/index.js";

export interface OpenCodePluginDependencies {
  readonly evaluateBashGuards?: BashGuardEvaluator;
  readonly evaluateConfiguredBash?: BashConfiguredEvaluator;
}

export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const guardEvaluator = dependencies.evaluateBashGuards ?? evaluateBashGuards;
  const permissionEvaluator = dependencies.evaluateConfiguredBash ?? evaluateConfiguredBash;

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
      const bashContext = bashAuthorizationContext();

      // ── Rule-based checks: hard-block clear violations ────────────
      const ghPrCreatePolicy = loadGhPrCreatePolicy();
      const guardReason = openCodeBashGuardBlockReason(command, bashContext, ghPrCreatePolicy, guardEvaluator);
      if (guardReason) throw new Error(guardReason);

      // ── LLM Judge: second pass for secret-adjacent commands ──────────
      if (shouldInvokeJudge(command)) {
        const verdict = await invokeJudge(command);
        if (verdict && !verdict.safe) {
          throw new Error(`Blocked by OpenCode safety policy (🧑‍⚖️ judge): ${verdict.reasoning}`);
        }
      }
    },

    // Older OpenCode releases invoke permission.ask with the parsed command.
    // Current releases use permission.asked below; retain this compatibility
    // route while they transition their plugin API.
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;

      const command = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!command) return;
      const decision = configuredPermission(command, permissionEvaluator);
      if (decision.kind === "allow" || decision.kind === "deny") output.status = decision.kind;
    },

    // Current OpenCode versions publish this event instead of invoking
    // permission.ask. Replying once resolves the pending native request.
    event: async ({ event }) => {
      if (!client || event.type !== "permission.asked" || event.properties.permission !== "bash") return;
      const command = event.properties.patterns.join(" && ");
      const decision = configuredPermission(command, permissionEvaluator);
      if (decision.kind === "allow") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "once" });
      } else if (decision.kind === "deny") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "reject", message: decision.reason });
      }
    },

    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash") return;
      const command = String((input.args as Record<string, unknown>).command ?? "");

      const summary = summariseKubectlSecret(command, bashAuthorizationContext());
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

function bashAuthorizationContext() {
  return Object.freeze({
    limits: loadBashAnalysisLimits(),
    initialEnvironment: { kind: "unavailable" as const },
  });
}

type BashGuardEvaluator = (options: BashGuardOptions) => BashGuardEvaluation;
type BashConfiguredEvaluator = (options: BashConfiguredOptions) => BashConfiguredEvaluation;

function configuredPermission(command: string, evaluate: BashConfiguredEvaluator) {
  return evaluate({ source: command, initialEnvironment: { kind: "unavailable" } }).permission;
}

/** Map one deny-only core guard evaluation to OpenCode's existing messages. */
export function openCodeBashGuardBlockReason(
  command: string,
  context: BashAuthorizationContext,
  ghPrCreatePolicy: ReturnType<typeof loadGhPrCreatePolicy> = {
    enabled: false,
    allowedRepositories: [],
    allowedOrganizations: [],
  },
  evaluate: BashGuardEvaluator = evaluateBashGuards,
): string | null {
  const result = evaluate({ source: command, ...context, ghPrCreatePolicy });
  if (result.kind === "pass") return null;
  return result.policy.name === "github-http"
    ? result.reason
    : `Blocked by OpenCode safety policy: ${result.reason}`;
}
