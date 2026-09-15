// OpenCode Plugin adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between OpenCode's plugin API and core decision functions.

import type { Plugin } from "@opencode-ai/plugin";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  analyzeGhApiCommand,
  analyzeGenericReadOnlyCommand,
  analyzeGhPrCreateAuthorization,
  analyzeGhReadOnlyCommand,
  analyzeHelmReadOnlyCommand,
  analyzeStrictReadOnlyCommand,
  appendAuditRecord,
  checkWebfetchUrl,
  defaultAuditPath,
  discoverWasmDir,
  evaluateBashGuards,
  initBashParser,
  isProfileEnabled,
  loadBashAnalysisLimits,
  loadGhPrCreatePolicy,
  mapOpenCodeBashStatus,
  isSecretPath,
  summariseKubectlSecret,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type BashAuthorizationContext,
  type BashGuardEvaluation,
  type BashGuardOptions,
  type JudgeProvider,
} from "../src/index.js";

export interface OpenCodePluginDependencies {
  readonly evaluateBashGuards?: BashGuardEvaluator;
}

export async function createOpenCodePlugin(dependencies: OpenCodePluginDependencies = {}) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const guardEvaluator = dependencies.evaluateBashGuards ?? evaluateBashGuards;

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

    // `tool.execute.before` can only throw to hard-block; it has no channel
    // to auto-approve. `permission.ask` is the actual override point: it
    // fires when OpenCode's native permission gate is about to ask, and a
    // plugin can set `output.status` to "allow"/"deny"/"ask" to decide the
    // outcome instead. `input.pattern` carries the full command text for a
    // bash permission request (populated from the parsed shell command by
    // OpenCode's own shell tool -- see packages/opencode/src/tool/shell.ts).
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;

      const command = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!command) return;
      const bashContext = bashAuthorizationContext();

      const ghPrCreatePolicy = loadGhPrCreatePolicy();
      if (ghPrCreatePolicy.enabled) {
        const ghPrCreateAnalysis = analyzeGhPrCreateAuthorization(command, ghPrCreatePolicy, bashContext);
        output.status = mapOpenCodeBashStatus(output.status, ghPrCreateAnalysis.verdict);
        if (ghPrCreateAnalysis.verdict.kind !== "neutral") return;
      }

      if (isProfileEnabled("readOnlyBash")) {
        const decision = analyzeGenericReadOnlyCommand(command, bashContext);
        output.status = mapOpenCodeBashStatus(output.status, decision);
        if (decision.kind !== "ignore") return;
      }

      if (isProfileEnabled("ghReadOnly")) {
        const decision = analyzeGhReadOnlyCommand(command, bashContext);
        output.status = mapOpenCodeBashStatus(output.status, decision);
        if (decision.kind !== "ignore") return;
      }

      if (isProfileEnabled("helmReadOnly")) {
        const decision = analyzeHelmReadOnlyCommand(command, bashContext);
        output.status = mapOpenCodeBashStatus(output.status, decision);
        if (decision.kind !== "ignore") return;
      }

      // TODO: Replace adapter-owned profile loading, command selection, and
      // repeated parsing with one configuration-driven core Bash evaluation.
      const strictProfiles = [
        ["argocdReadOnly", "argocd"], ["cosignReadOnly", "cosign"], ["craneReadOnly", "crane"],
        ["dockerReadOnly", "docker"], ["jfrogReadOnly", "jf"], ["jfrogReadOnly", "jfrog"],
        ["kubectlReadOnly", "kubectl"], ["nixReadOnly", "nix"],
        ["nixEnvReadOnly", "nix-env"], ["nixStoreReadOnly", "nix-store"], ["ocReadOnly", "oc"],
        ["podmanReadOnly", "podman"], ["podmanComposeReadOnly", "podman-compose"], ["skopeoReadOnly", "skopeo"],
        ["tofuReadOnly", "tofu"], ["npmReadOnly", "npm"], ["pipReadOnly", "pip"],
        ["uvReadOnly", "uv"], ["yarnReadOnly", "yarn"],
      ] as const;
      for (const [profile, executable] of strictProfiles) {
        if (!isProfileEnabled(profile)) continue;
        const decision = analyzeStrictReadOnlyCommand(command, executable, bashContext);
        output.status = mapOpenCodeBashStatus(output.status, decision);
        if (decision.kind !== "ignore") return;
      }

      if (!isProfileEnabled("ghApiReadOnly")) return;
      output.status = mapOpenCodeBashStatus(output.status, analyzeGhApiCommand(command, bashContext));
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

export default async () => createOpenCodePlugin();

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
