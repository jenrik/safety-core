// pi ExtensionAPI adapter for the shared LLM safety hook.
//
// Delegates all policy decisions to ../src/*. This file only knows how
// to translate between the pi event model and core decision functions.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

import { createBashTool } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model, SimpleStreamOptions } from "@earendil-works/pi-ai";
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
  analyzeGhPrCreateAuthorization,
  defaultAuditPath,
  discoverWasmDir,
  initBashParser,
  loadBashAnalysisLimits,
  isSecretPath,
  loadGhPrCreatePolicy,
  parseBashForSecretRead,
  summariseKubectlSecret,
  appendAuditRecord,
  setJudgeVerdict,
  getJudgeVerdict,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  shouldBlockPiBash,
  createCompletionJudge,
  type JudgeProvider,
} from "../src/index.js";

// ── Module state ──────────────────────────────────────────────────────
// judgeModelOverride wins over settings.json; set by /safety-core menu.
// Values are persisted as provider/model-id, so any configured Pi provider can
// supply the judge.
let judgeModelOverride: string | undefined;
let _sessionCwd: string | undefined;
let _sessionModel: Model<any> | undefined;
let _modelRegistry: {
  getAvailable(): Model<any>[];
  getAll(): Model<any>[];
} | undefined;

// ModelRegistry intentionally exposes catalog and credential APIs, but not
// model execution. Its backing ModelRuntime is what Pi itself uses for every
// configured provider, including providers registered by other extensions.
// Keep the compatibility boundary narrow and fail open if Pi changes it.
interface ModelRuntimeAccess {
  completeSimple(
    model: Model<any>,
    context: Context,
    options?: SimpleStreamOptions,
  ): Promise<AssistantMessage>;
}

function getModelRuntime(): ModelRuntimeAccess | undefined {
  const registry = _modelRegistry as unknown as { runtime?: ModelRuntimeAccess } | undefined;
  return typeof registry?.runtime?.completeSimple === "function"
    ? registry.runtime
    : undefined;
}

async function refreshJudge(): Promise<void> {
  setJudgeProvider(await buildJudgeProvider());
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

    // Use Pi's model runtime so every authenticated provider/model available
    // to this instance can be selected as the judge.
    _sessionCwd = ctx.cwd;
    _sessionModel = ctx.model;
    _modelRegistry = ctx.modelRegistry;
    await refreshJudge();
  });

  // ── /safety-core command ─────────────────────────────────────────────
  pi.registerCommand("safety-core", {
    description: "Configure safety-core settings (judge model)",
    handler: async (_args, ctx) => {
      _sessionCwd = ctx.cwd;
      _sessionModel = ctx.model;
      _modelRegistry = ctx.modelRegistry;

      const currentModel = judgeModelOverride ?? readSettings("safety.judgeModel", ctx.cwd);
      const models = getAvailableJudgeModels(ctx.modelRegistry);
      const options = [
        {
          value: "(default)",
          label: "Default (active model: " + formatModel(_sessionModel) + ")",
        },
        ...models.map((model) => ({
          value: modelKey(model),
          label: formatModel(model),
        })),
      ];
      const labels = options.map(({ value, label }) =>
        value === currentModel ? "★ " + label + " (current)" : label,
      );

      const choice = await ctx.ui.select("Judge model for safety checks:", labels);
      if (choice == null) return;

      const selected = options[labels.indexOf(choice)];
      if (!selected) return;
      judgeModelOverride = selected.value === "(default)" ? undefined : selected.value;

      // Persist to project settings so it survives restarts.
      writeSettings("safety.judgeModel", judgeModelOverride, ctx.cwd);

      // Rebuild the judge provider immediately.
      await refreshJudge();

      ctx.ui.notify(
        judgeModelOverride
          ? `Judge model: ${judgeModelOverride}`
          : "Judge model: default",
        "info",
      );
    },
  });

  // The default judge follows the active model. Keep it synchronized when the
  // user switches models; an explicit /safety-core choice is retained.
  pi.on("model_select", async (event, ctx) => {
    _sessionCwd = ctx.cwd;
    _sessionModel = event.model;
    _modelRegistry = ctx.modelRegistry;
    await refreshJudge();
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
      const bashContext = bashAuthorizationContext();

      // ── Rule-based checks: hard-block clear violations ────────────
      const secretReason = parseBashForSecretRead(command, bashContext);
      if (secretReason) {
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: `Blocked: ${secretReason}`,
        });
        ctx.ui.notify(`Blocked ${secretReason}`, "warning");
        return { block: true, reason: SECRET_BLOCK_MESSAGE };
      }

      const githubReason = checkBashForGithub(command, bashContext);
      if (githubReason) {
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: "Blocked: direct GitHub HTTP request",
        });
        ctx.ui.notify("Blocked direct GitHub HTTP request", "warning");
        return { block: true, reason: githubReason };
      }

      const ghPrCreatePolicy = loadGhPrCreatePolicy();
      const ghPrCreateAnalysis = ghPrCreatePolicy.enabled
        ? analyzeGhPrCreateAuthorization(command, ghPrCreatePolicy, bashContext)
        : null;
      if (ghPrCreateAnalysis && shouldBlockPiBash(ghPrCreateAnalysis.verdict)) {
        const reason = ghPrCreateAnalysis.policies.find((policy) => policy.decision === "deny")?.reason
          ?? "Pull-request creation is blocked";
        setJudgeVerdict(event.toolCallId, {
          safe: false,
          reasoning: `Blocked: ${reason}`,
        });
        ctx.ui.notify(`Blocked ${reason}`, "warning");
        return { block: true, reason };
      }

      // For kubectl commands that are clearly dangerous, block immediately.
      // For borderline kubectl commands (e.g. `kubectl get Secret`), defer to
      // the LLM judge below instead of blocking outright.
      const kubectlDecision = checkBashForKubectlSecret(command, bashContext);
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

    const summary = summariseKubectlSecret(command, bashAuthorizationContext());
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
      if (verdict?.fromLLM) {
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
 * Build a judge through Pi's own ModelRuntime. This preserves each provider's
 * native authentication, request format, and custom extension implementation.
 */
async function buildJudgeProvider(): Promise<JudgeProvider | null> {
  const registry = _modelRegistry;
  const runtime = getModelRuntime();
  if (!registry || !runtime) return null;

  const configured = judgeModelOverride ?? readSettings("safety.judgeModel", _sessionCwd);
  const model = resolveJudgeModel(configured, getAvailableJudgeModels(registry), _sessionModel);
  if (!model) return null;

  return createCompletionJudge(async (systemPrompt, userPrompt, signal) => {
    const response = await runtime.completeSimple(
      model,
      {
        systemPrompt,
        messages: [{ role: "user", content: userPrompt, timestamp: Date.now() }],
      },
      { maxTokens: 256, temperature: 0, signal, maxRetries: 0 },
    );

    if (response.stopReason === "error") {
      throw new Error(response.errorMessage ?? "Judge request failed");
    }

    return response.content
      .filter((block): block is { type: "text"; text: string } => block.type === "text")
      .map((block) => block.text)
      .join("");
  });
}

function getAvailableJudgeModels(registry: {
  getAvailable(): Model<any>[];
  getAll(): Model<any>[];
}): Model<any>[] {
  // getAvailable is Pi's authenticated, credential-aware catalog. Fall back to
  // the full catalog for older Pi releases whose snapshot is not populated yet;
  // execution still performs Pi's normal authentication check.
  const models = registry.getAvailable();
  return (models.length > 0 ? models : registry.getAll())
    .slice()
    .sort((a, b) => modelKey(a).localeCompare(modelKey(b)));
}

function modelKey(model: Model<any>): string {
  return model.provider + "/" + model.id;
}

function formatModel(model: Model<any> | undefined): string {
  return model
    ? modelKey(model) + (model.name === model.id ? "" : " (" + model.name + ")")
    : "none";
}

function resolveJudgeModel(
  configured: string | undefined,
  models: Model<any>[],
  active: Model<any> | undefined,
): Model<any> | undefined {
  if (!configured) return active;

  const exact = models.find((model) => modelKey(model) === configured);
  if (exact) return exact;

  // Backwards compatibility with the previous bare model-id setting.
  return models.find((model) => model.provider === active?.provider && model.id === configured)
    ?? models.find((model) => model.id === configured);
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

function bashAuthorizationContext() {
  return Object.freeze({
    limits: loadBashAnalysisLimits(),
    initialEnvironment: { kind: "unavailable" as const },
  });
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
