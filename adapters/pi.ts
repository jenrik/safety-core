// pi ExtensionAPI adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between the pi event model and core decision functions.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  basename,
  checkBashForGithub,
  checkBashForKubectlSecret,
  checkWebfetchUrl,
  defaultAuditPath,
  isSecretPath,
  parseBashForSecretRead,
  summariseKubectlSecret,
  appendAuditRecord,
} from "../src/index.js";

export default function (pi: ExtensionAPI) {
  // ── PreToolUse: block dangerous tool invocations ───────────────────────
  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "read") {
      const path = (event.input as { path?: string })?.path;
      if (path && isSecretPath(path)) {
        ctx.ui.notify(`Blocked read of secret file: ${basename(path)}`, "warning");
        return { block: true, reason: SECRET_BLOCK_MESSAGE };
      }
    }

    if (event.toolName === "webfetch" || event.toolName === "web_fetch") {
      const url = (event.input as { url?: string })?.url ?? "";
      const reason = checkWebfetchUrl(url);
      if (reason) {
        ctx.ui.notify("Blocked direct GitHub HTTP request", "warning");
        return { block: true, reason };
      }
    }

    if (event.toolName === "bash") {
      const command = (event.input as { command?: string })?.command ?? "";

      const secretReason = parseBashForSecretRead(command);
      if (secretReason) {
        ctx.ui.notify(`Blocked ${secretReason}`, "warning");
        return { block: true, reason: SECRET_BLOCK_MESSAGE };
      }

      const githubReason = checkBashForGithub(command);
      if (githubReason) {
        ctx.ui.notify("Blocked direct GitHub HTTP request", "warning");
        return { block: true, reason: githubReason };
      }

      const kubectlReason = checkBashForKubectlSecret(command);
      if (kubectlReason) {
        ctx.ui.notify("Blocked kubectl Secret exposure", "warning");
        return { block: true, reason: kubectlReason };
      }
    }
  });

  // ── PostToolUse: audit + reminder ──────────────────────────────────────
  pi.on("tool_result", async (event, _ctx) => {
    if (event.toolName !== "bash") return;
    const command = (event.input as { command?: string })?.command ?? "";

    // Kubectl-secret audit trail (never logs raw command; --from-literal args
    // can carry the secret value on the argv line).
    const summary = summariseKubectlSecret(command);
    if (summary) {
      await appendAuditRecord(defaultAuditPath("pi"), {
        timestamp: new Date().toISOString(),
        ...summary,
      }).catch(() => {});
    }

    // Inject a reminder for the main agent when the executed command matched a
    // secret-shaped keyword. Uses the same shape as the claude-code hook.
    if (matchesSecretKeyword(command)) {
      return {
        content: appendTextToContent(event.content, `\n\n${SECRET_COMMAND_REMINDER}`),
      };
    }
  });

  pi.on("session_start", async (_event, ctx) => {
    ctx.ui.setStatus("safety-hook", "safety: guarded");
  });
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function matchesSecretKeyword(command: string): boolean {
  const haystack = command.toLowerCase();
  return SECRET_PATTERNS.some((p) =>
    haystack.includes(p.toLowerCase().replaceAll("*", "")),
  );
}

type TextBlock = { type: "text"; text: string };
type ContentBlock = TextBlock | { type: string; [k: string]: unknown };

function appendTextToContent(
  content: unknown,
  suffix: string,
): ContentBlock[] | string {
  if (typeof content === "string") return content + suffix;
  if (!Array.isArray(content)) return [{ type: "text", text: suffix }];

  const blocks = content as ContentBlock[];
  const lastText = [...blocks].reverse().find((b) => b.type === "text") as TextBlock | undefined;
  if (lastText) {
    return blocks.map((b) =>
      b === lastText ? { ...b, text: (b as TextBlock).text + suffix } : b,
    );
  }
  return [...blocks, { type: "text", text: suffix }];
}
