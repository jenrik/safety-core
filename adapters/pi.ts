// pi ExtensionAPI adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between the pi event model and core decision functions.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

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
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type JudgeProvider,
} from "../src/index.js";

// ── Module state ──────────────────────────────────────────────────────
// judgeModelOverride wins over settings.json; set by /safety-core menu.
let judgeModelOverride: string | undefined;
let _sessionCwd: string | undefined;
let _sessionProvider: string | undefined;

function refreshJudge(): void {
  setJudgeProvider(buildJudgeProvider(_sessionProvider, _sessionCwd));
}

export default function (pi: ExtensionAPI) {
  // ── Initialise the bash parser + LLM judge ────────────────────────────
  pi.on("session_start", async (_event, ctx) => {
    try {
      const wasmDir = discoverWasmDir(import.meta.url);
      await initBashParser(wasmDir);
    } catch {
      // If WASM loading fails, the parser stays null and consumers fall
      // back to safe defaults (no commands parsed → no blocks).
    }

    // Wire up LLM judge using Pi's existing provider configuration.
    // Pi sets ANTHROPIC_API_KEY / OPENAI_API_KEY from auth.json at startup.
    // ctx.model tells us which provider is active so we can pick the right API.
    // The "safety.judgeModel" setting (configurable via /safety-core)
    // overrides the default judge model.
    _sessionCwd = ctx.cwd;
    _sessionProvider = ctx.model?.provider;
    refreshJudge();
  });

  // ── /safety-core command ─────────────────────────────────────────────
  pi.registerCommand("safety-core", {
    description: "Configure safety-core settings (judge model)",
    handler: async (_args, ctx) => {
      const currentModel =
        judgeModelOverride ?? readSettings("safety.judgeModel", ctx.cwd);
      const isAnthropic =
        _sessionProvider === "anthropic" || Boolean(process.env.ANTHROPIC_API_KEY);

      const modelOptions = isAnthropic
        ? ["(default)", "claude-haiku-4-5", "claude-sonnet-4-6", "claude-sonnet-5", "claude-opus-4-7", "claude-opus-4-8"]
        : ["(default)", "gpt-4o-mini", "gpt-4.1", "gpt-5", "o4-mini"];

      const labels = modelOptions.map((m) =>
        m === "(default)"
          ? `Default (${isAnthropic ? "claude-haiku-4-5" : "gpt-4o-mini"})`
          : m === currentModel
            ? `★ ${m} (current)`
            : m,
      );

      const choice = await ctx.ui.select("Judge model for safety checks:", labels);
      if (choice == null) return;

      const newModel = modelOptions[labels.indexOf(choice)];
      judgeModelOverride = newModel === "(default)" ? undefined : newModel;

      // Persist to project settings so it survives restarts.
      writeSettings("safety.judgeModel", judgeModelOverride, ctx.cwd);

      // Rebuild the judge provider immediately.
      _sessionCwd = ctx.cwd;
      _sessionProvider = ctx.model?.provider;
      refreshJudge();

      ctx.ui.notify(
        judgeModelOverride
          ? `Judge model: ${judgeModelOverride}`
          : "Judge model: default",
        "info",
      );
    },
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

      // ── Rule-based checks: hard-block clear violations ────────────
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

      // For kubectl commands that are clearly dangerous, block immediately.
      // For borderline kubectl commands (e.g. `kubectl get Secret`), defer to
      // the LLM judge below instead of blocking outright.
      const kubectlDecision = checkBashForKubectlSecret(command);
      if (kubectlDecision && !kubectlDecision.startsWith("kubectl get Secret")) {
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: "Blocked: kubectl Secret exposure",
        });
        ctx.ui.notify("Blocked kubectl Secret exposure", "warning");
        return { block: true, reason: kubectlDecision };
      }

      // ── LLM Judge: second pass for secret-adjacent commands ──────────
      //
      // Commands that mention secret-shaped keywords but passed rule-based
      // checks may still be dangerous (e.g. `kubectl get secret foo -o yaml`).
      // The judge provider was wired up in session_start from Pi's own model
      // configuration — no separate env-var config needed.
      if (shouldInvokeJudge(command)) {
        const verdict = await invokeJudge(command, ctx.signal);
        if (verdict) {
          setJudgeVerdict(event.toolCallId, verdict);
          if (!verdict.safe) {
            ctx.ui.notify(`🧑‍⚖️ Blocked: ${verdict.reasoning}`, "warning");
            return { block: true, reason: verdict.reasoning };
          }
        }
        // Judge approved (or unavailable) — let the command proceed.
        return;
      }

      // Command passed all safety checks.
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

    const summary = summariseKubectlSecret(command);
    if (summary) {
      await appendAuditRecord(defaultAuditPath("pi"), {
        timestamp: new Date().toISOString(),
        ...summary,
      }).catch(() => {});
    }

    if (matchesSecretKeyword(command)) {
      return {
        content: appendTextToContent(event.content, `\n\n${SECRET_COMMAND_REMINDER}`),
      };
    }
  });

  // ── Bash tool override: judge annotation in TUI ────────────────────────
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
  });
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Build a JudgeProvider from Pi's own provider configuration.
 *
 * Uses the harness's existing API keys (set by Pi from auth.json)
 * and the active provider to decide which API to call.  Reads the
 * optional `safety.judgeModel` key from Pi's settings.json (global
 * and project-local, merged with project winning).
 */
function buildJudgeProvider(provider?: string, cwd?: string): JudgeProvider | null {
  const judgeModel = judgeModelOverride ?? readSettings("safety.judgeModel", cwd);

  // Try Anthropic first (matches ctx.model.provider for Anthropic models).
  if (provider === "anthropic" || process.env.ANTHROPIC_API_KEY) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (apiKey) return createAnthropicJudge({ apiKey, model: judgeModel });
  }

  // Try OpenAI-compatible.
  if (process.env.OPENAI_API_KEY) {
    const apiKey = process.env.OPENAI_API_KEY;
    if (apiKey) return createOpenAIJudge({ apiKey, model: judgeModel });
  }

  // No usable API key found — judge stays disabled (fail-open).
  return null;
}

/**
 * Read a dotted-path setting from Pi's merged settings.json files.
 *
 * Looks at ~/.pi/agent/settings.json (global) first, then merges
 * .pi/settings.json from cwd (project wins).  Returns undefined if
 * the key doesn't exist or files can't be read.
 */
function readSettings(path: string, cwd?: string): string | undefined {
  const merged: Record<string, unknown> = {};

  // Global settings
  try {
    const globalPath = join(homedir(), ".pi", "agent", "settings.json");
    const raw = readFileSync(globalPath, "utf-8");
    Object.assign(merged, JSON.parse(raw));
  } catch { /* ignore */ }

  // Project settings (override global)
  if (cwd) {
    try {
      const projectPath = join(cwd, ".pi", "settings.json");
      const raw = readFileSync(projectPath, "utf-8");
      Object.assign(merged, JSON.parse(raw));
    } catch { /* ignore */ }
  }

  // Navigate dotted path: "safety.judgeModel" → merged.safety?.judgeModel
  const parts = path.split(".");
  let value: unknown = merged;
  for (const part of parts) {
    if (value == null || typeof value !== "object") return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return typeof value === "string" ? value : undefined;
}

/**
 * Write a dotted-path value to the project .pi/settings.json file.
 *
 * Reads the existing file, sets the nested key, and writes back.
 * Creates parent directories as needed.
 */
function writeSettings(path: string, value: string | undefined, cwd?: string): void {
  if (!cwd) return;

  const settingsPath = join(cwd, ".pi", "settings.json");
  let obj: Record<string, unknown> = {};

  try {
    const raw = readFileSync(settingsPath, "utf-8");
    obj = JSON.parse(raw);
  } catch { /* start fresh */ }

  if (typeof obj !== "object" || obj == null) obj = {};

  // Navigate to the parent of the dotted path.
  const parts = path.split(".");
  let cursor: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (cursor[parts[i]] == null || typeof cursor[parts[i]] !== "object") {
      cursor[parts[i]] = {};
    }
    cursor = cursor[parts[i]] as Record<string, unknown>;
  }

  const last = parts[parts.length - 1];
  if (value === undefined) {
    delete cursor[last];
  } else {
    cursor[last] = value;
  }

  try {
    writeFileSync(settingsPath, JSON.stringify(obj, null, 2) + "\n", {
      mode: 0o644,
    });
  } catch {
    // Directory may not exist.
    try {
      mkdirSync(dirname(settingsPath), { recursive: true });
      writeFileSync(settingsPath, JSON.stringify(obj, null, 2) + "\n", {
        mode: 0o644,
      });
    } catch { /* silently fail */ }
  }
}

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
