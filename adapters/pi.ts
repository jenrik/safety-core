// pi ExtensionAPI adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between the pi event model and core decision functions.

import { createBashTool } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Container, Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

import {
  SECRET_BLOCK_MESSAGE,
  SECRET_COMMAND_REMINDER,
  SECRET_PATTERNS,
  basename,
  checkBashForGithub,
  checkBashForKubectlSecret,
  checkWebfetchUrl,
  defaultAuditPath,
  discoverWasmDir,
  initBashParser,
  isSecretPath,
  parseBashForSecretRead,
  summariseKubectlSecret,
  appendAuditRecord,
  setJudgeVerdict,
  getJudgeVerdict,
} from "../src/index.js";

export default function (pi: ExtensionAPI) {
  // ── Initialise the bash parser ────────────────────────────────────────
  pi.on("session_start", async (_event, _ctx) => {
    try {
      const wasmDir = discoverWasmDir(import.meta.url);
      await initBashParser(wasmDir);
    } catch {
      // If WASM loading fails, the parser stays null and consumers fall
      // back to safe defaults (no commands parsed → no blocks).
    }
  });

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
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: `Blocked: ${secretReason}`,
        });
        ctx.ui.notify(`Blocked ${secretReason}`, "warning");
        return { block: true, reason: SECRET_BLOCK_MESSAGE };
      }

      const githubReason = checkBashForGithub(command);
      if (githubReason) {
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: "Blocked: direct GitHub HTTP request",
        });
        ctx.ui.notify("Blocked direct GitHub HTTP request", "warning");
        return { block: true, reason: githubReason };
      }

      const kubectlReason = checkBashForKubectlSecret(command);
      if (kubectlReason) {
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: "Blocked: kubectl Secret exposure",
        });
        ctx.ui.notify("Blocked kubectl Secret exposure", "warning");
        return { block: true, reason: kubectlReason };
      }

      // Command passed all safety checks — store judge verdict for TUI annotation.
      setJudgeVerdict(event.toolCallId, {
        safe: true,
        reasoning: "Safety check passed — no policy violations detected",
      });
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

  // ── Bash tool override: judge annotation in TUI ────────────────────────
  //
  // Override the built-in bash tool to inject a safety-review annotation
  // (🧑‍⚖️ ✅ / ❌ + reasoning) at the top of the tool invocation box.
  // Execution delegates to createBashTool so we keep full built-in behaviour
  // (truncation, temp files, streaming, etc.).  renderResult is inherited
  // from the built-in tool automatically.

  const bashSchema = Type.Object({
    command: Type.String({
      description:
        "Execute a bash command. Returns stdout and stderr. Output is truncated to 2000 lines or 50KB (whichever is hit first). If truncated, full output is saved to a temp file. Optionally provide a timeout in seconds.",
    }),
    timeout: Type.Optional(Type.Number({
      description: "Optional timeout in seconds.",
    })),
  });

  pi.registerTool({
    name: "bash",
    label: "Bash",
    description:
      "Execute a bash command. Returns stdout and stderr. Output is truncated to last 2000 lines or 50KB (whichever is hit first). If truncated, full output is saved to a temp file. Optionally provide a timeout in seconds.",
    parameters: bashSchema,

    async execute(toolCallId, params, signal, onUpdate, ctx) {
      const bashTool = createBashTool(ctx.cwd);
      return bashTool.execute(toolCallId, params, signal, onUpdate, ctx);
    },

    renderCall(args, theme, context) {
      const container = new Container();

      // ── Judge annotation line ────────────────────────────────────
      const verdict = getJudgeVerdict(context.toolCallId);
      if (verdict) {
        const icon = verdict.safe ? "✅" : "❌";
        container.addChild(
          new Text(
            `🧑‍⚖️ ${icon} ${theme.italic(verdict.reasoning)}`,
            0,
            0,
          ),
        );
      }

      // ── Command display (matches built-in style) ─────────────────
      const command = args.command || "...";
      const timeout = args.timeout;
      const timeoutSuffix = timeout
        ? theme.fg("muted", ` (timeout ${timeout}s)`)
        : "";
      container.addChild(
        new Text(
          theme.fg("toolTitle", theme.bold(`$ ${command}`)) + timeoutSuffix,
          0,
          0,
        ),
      );

      return container;
    },

    // renderResult is omitted — the built-in Bash result renderer
    // (with truncation footer, timing, streaming) is used automatically.
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
