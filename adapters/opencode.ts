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
  appendAuditRecord,
  checkBashForGithub,
  checkBashForKubectlSecret,
  checkWebfetchUrl,
  defaultAuditPath,
  discoverWasmDir,
  initBashParser,
  isProfileEnabled,
  isSecretPath,
  parseBashForSecretRead,
  summariseKubectlSecret,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type JudgeProvider,
} from "../src/index.js";

// Initialise the bash parser eagerly (plugin factory can be async).
const initPromise = initBashParser(discoverWasmDir(import.meta.url)).catch(() => {});

export default (async () => {
  await initPromise;

  // Wire up LLM judge using OpenCode's provider configuration.
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
      const secretReason = parseBashForSecretRead(command);
      if (secretReason) {
        throw new Error(`Blocked by OpenCode safety policy: ${secretReason}`);
      }

      const githubReason = checkBashForGithub(command);
      if (githubReason) {
        throw new Error(githubReason);
      }

      const kubectlDecision = checkBashForKubectlSecret(command);
      if (kubectlDecision && !kubectlDecision.startsWith("kubectl get Secret")) {
        throw new Error(`Blocked by OpenCode safety policy: ${kubectlDecision}`);
      }

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
      if (!isProfileEnabled("ghApiReadOnly")) return;

      const command = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!command) return;

      const decision = analyzeGhApiCommand(command);
      if (decision.kind === "allow") output.status = "allow";
      else if (decision.kind === "deny") output.status = "deny";
      // defer / ignore: leave output.status untouched (native permission tree decides).
    },

    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash") return;
      const command = String((input.args as Record<string, unknown>).command ?? "");

      const summary = summariseKubectlSecret(command);
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
})();

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
