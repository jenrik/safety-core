// OpenCode Plugin adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between OpenCode's plugin API and core decision functions.

import type { Plugin } from "@opencode-ai/plugin";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  appendAuditRecord,
  checkBashForGithub,
  checkBashForKubectlSecret,
  checkWebfetchUrl,
  defaultAuditPath,
  discoverWasmDir,
  initBashParser,
  isSecretPath,
  parseBashForSecretRead,
  summariseKubectlSecret,
} from "../src/index.js";

// Initialise the bash parser eagerly (plugin factory can be async).
const initPromise = initBashParser(discoverWasmDir(import.meta.url)).catch(() => {});

export default (async () => {
  await initPromise;

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
      const reason =
        parseBashForSecretRead(command) ??
        checkBashForGithub(command) ??
        checkBashForKubectlSecret(command);
      if (reason) throw new Error(`Blocked by OpenCode safety policy: ${reason}`);
    },

    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash") return;
      const command = String((input.args as Record<string, unknown>).command ?? "");

      // Kubectl-secret audit trail (never logs raw command; --from-literal args
      // can carry the secret value on the argv line).
      const summary = summariseKubectlSecret(command);
      if (summary) {
        await appendAuditRecord(defaultAuditPath("opencode"), {
          timestamp: new Date().toISOString(),
          ...summary,
        }).catch(() => {});
      }

      // Reminder for the model when the command matched a secret-shaped keyword.
      if (matchesSecretKeyword(command)) {
        output.output += `\n\n${SECRET_COMMAND_REMINDER}`;
      }
    },
  } satisfies Plugin;
})();

// ─── helpers ─────────────────────────────────────────────────────────────────

function matchesSecretKeyword(command: string): boolean {
  const haystack = command.toLowerCase();
  return SECRET_PATTERNS.some((p) =>
    haystack.includes(p.toLowerCase().replaceAll("*", "")),
  );
}
