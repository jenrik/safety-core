import { createBashTool } from "@earendil-works/pi-coding-agent";
import { getSettingsListTheme } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { AssistantMessage, Context, Model, SimpleStreamOptions } from "@earendil-works/pi-ai";
import { Container, type SettingItem, SettingsList, Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

import {
  SECRET_BLOCK_MESSAGE,
  checkWebfetchUrl,
  discoverWasmDir,
  evaluateLoadedPolicies,
  initBashParser,
  isSecretPath,
  loadPolicyRuntime,
  nodeExecutableFilesystem,
  completePolicyInitialEnvironment,
  createPolicyRuntimeReloader,
  createCompletionJudge,
  setJudgeVerdict,
  getJudgeVerdict,
  invokeJudge,
  setJudgeProvider,
  shouldInvokeJudge,
  type BashPolicyEvaluation,
  type LoadedPolicyRuntime,
  type ExecutableFilesystem,
  type JudgeProvider,
  type PiAdapterConfig,
} from "../src/index.js";

export interface PiExtensionDependencies {
  readonly runtime?: Promise<LoadedPolicyRuntime>;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: (runtime: LoadedPolicyRuntime, source: string, context?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem }) => BashPolicyEvaluation;
  readonly executableFilesystem?: ExecutableFilesystem;
}

interface PiSessionSettings {
  readonly autoApprove: boolean;
  readonly judgeModel?: string;
}

interface PiSessionSettingsEntry {
  readonly autoApprove: boolean;
  readonly judgeModel: string | null;
}

interface ModelRuntimeAccess {
  completeSimple(model: Model<any>, context: Context, options?: SimpleStreamOptions): Promise<AssistantMessage>;
}

const PI_SETTINGS_ENTRY = "safety-core-pi-settings";
const ACTIVE_MODEL = "active model";

export function createPiExtension(pi: ExtensionAPI, dependencies: PiExtensionDependencies = {}) {
  const parserReady = initBashParser(discoverWasmDir(import.meta.url));
  void parserReady.catch(() => {});
  const runtime = createPolicyRuntimeReloader(dependencies.loadRuntime ?? loadPolicyRuntime, dependencies.runtime);
  let poisoned: string | undefined;
  const ensureRuntime = (cwd: string) => runtime.ensure(cwd);
  const executableFilesystem = dependencies.executableFilesystem ?? nodeExecutableFilesystem;
  const evaluate = dependencies.evaluatePolicies ?? ((runtime, source, context) => evaluateLoadedPolicies(runtime, source, completePolicyInitialEnvironment(process.env), context));
  let settings: PiSessionSettings = { autoApprove: false };
  let activeModel: Model<any> | undefined;
  let modelRegistry: { getAvailable(): Model<any>[]; getAll(): Model<any>[] } | undefined;

  const refreshJudge = async () => {
    setJudgeProvider(await buildJudgeProvider(settings.judgeModel, activeModel, modelRegistry));
  };
  const restoreSettings = async (ctx: ExtensionContext) => {
    const runtime = await ensureRuntime(ctx.cwd);
    settings = resolvePiSessionSettings(sessionEntries(ctx), runtime.config.pi);
    activeModel = ctx.model;
    modelRegistry = ctx.modelRegistry;
    await refreshJudge();
  };
  const reloadPolicies = async (ctx: ExtensionContext) => {
    try {
      await runtime.reload(ctx.cwd);
      poisoned = undefined;
      await restoreSettings(ctx);
      ctx.ui.notify("Safety policies reloaded", "info");
    } catch (error) {
      ctx.ui.notify(policyFailureReason(error), "error");
    }
  };
  const persistSettings = () => {
    pi.appendEntry<PiSessionSettingsEntry>(PI_SETTINGS_ENTRY, {
      autoApprove: settings.autoApprove,
      judgeModel: settings.judgeModel ?? null,
    });
  };

  pi.on("session_start", async (_event, ctx) => {
    try {
      await parserReady;
      await restoreSettings(ctx);
    } catch (error) {
      poisoned = policyFailureReason(error);
      throw new Error(poisoned);
    }
  });

  pi.on("session_tree", async (_event, ctx) => {
    if (poisoned) return;
    try {
      await restoreSettings(ctx);
    } catch (error) {
      poisoned = policyFailureReason(error);
    }
  });

  pi.on("model_select", async (event, ctx) => {
    activeModel = event.model;
    modelRegistry = ctx.modelRegistry;
    await refreshJudge();
  });

  pi.registerCommand("safety-core", {
    description: "Configure safety-core permissions and judge settings",
    handler: async (_args, ctx) => {
      if (ctx.mode !== "tui") {
        ctx.ui.notify("/safety-core requires TUI mode", "error");
        return;
      }
      try {
        await restoreSettings(ctx);
      } catch (error) {
        // A TUI user can repair an invalid policy and use this menu to retry.
        poisoned = policyFailureReason(error);
        ctx.ui.notify(poisoned, "error");
      }
      await ctx.ui.custom((tui, theme, _keybindings, done) => {
        const judgeChoices = availableJudgeModels(modelRegistry).map(modelKey);
        const currentJudge = settings.judgeModel ?? ACTIVE_MODEL;
        if (!judgeChoices.includes(currentJudge)) judgeChoices.unshift(currentJudge);
        const items: SettingItem[] = [
          {
            id: "auto-approve",
            label: "Auto-approve deferred commands",
            description: "Skip the one-time approval prompt for commands the policy defers. Safety blocks still apply.",
            currentValue: settings.autoApprove ? "enabled" : "disabled",
            values: ["disabled", "enabled"],
          },
          {
            id: "judge",
            label: "Judge",
            description: "Configure the model that reviews secret-adjacent commands.",
            currentValue: currentJudge,
            submenu: (currentValue, close) => new SettingsList(
              [{
                id: "judge-model",
                label: "Model",
                description: "Use the active model or choose an authenticated Pi provider/model.",
                currentValue,
                values: judgeChoices,
              }],
              1,
              getSettingsListTheme(),
              (_id, value) => close(value),
              () => close(),
            ),
          },
          {
            id: "reload-policies",
            label: "Reload policies from disk",
            description: "Replace the active policy set only after the configured policy sources load successfully.",
            currentValue: "reload",
            values: ["reload"],
          },
        ];
        const settingsList = new SettingsList(
          items,
          items.length,
          getSettingsListTheme(),
          async (id, value) => {
            if (id === "reload-policies") {
              await reloadPolicies(ctx);
              return;
            }
            if (id === "auto-approve") settings = { ...settings, autoApprove: value === "enabled" };
            if (id === "judge") settings = { ...settings, judgeModel: value === ACTIVE_MODEL ? undefined : value };
            persistSettings();
            await refreshJudge();
          },
          () => done(undefined),
        );
        const container = new Container();
        container.addChild(new Text(theme.fg("accent", theme.bold("Safety Core Settings")), 0, 0));
        container.addChild(settingsList);
        return {
          render: (width: number) => container.render(width),
          invalidate: () => container.invalidate(),
          handleInput: (data: string) => {
            settingsList.handleInput(data);
            tui.requestRender();
          },
        };
      });
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    if (event.toolName === "read") {
      const path = (event.input as { path?: string })?.path;
      if (path && isSecretPath(path)) return { block: true, reason: SECRET_BLOCK_MESSAGE };
    }
    if (event.toolName === "webfetch" || event.toolName === "web_fetch") {
      const reason = checkWebfetchUrl((event.input as { url?: string })?.url ?? "");
      if (reason) return { block: true, reason };
    }
    if (event.toolName !== "bash") return;
    const source = (event.input as { command?: string })?.command ?? "";
    if (poisoned) return { block: true, reason: poisoned };
    let result: BashPolicyEvaluation;
    try {
      await parserReady;
      result = evaluate(await ensureRuntime(ctx.cwd), source, { cwd: ctx.cwd, executableFilesystem });
    } catch (error) {
      poisoned = policyFailureReason(error);
      setJudgeVerdict(event.toolCallId, { safe: false, reasoning: poisoned });
      return { block: true, reason: poisoned };
    }
    if (result.decision === "deny") {
      const reason = policyReason(result, "Bash policy denied this command");
      setJudgeVerdict(event.toolCallId, { safe: false, reasoning: reason });
      return { block: true, reason };
    }
    if (result.decision === "defer" && !settings.autoApprove) {
      const approved = ctx.hasUI && typeof ctx.ui.confirm === "function"
        ? await ctx.ui.confirm("Safety permission required", "The configured policy could not fully authorize this command. Allow it once?", { signal: ctx.signal }).catch(() => false)
        : false;
      if (!approved) return { block: true, reason: "Command requires policy approval" };
    }
    // As in the other adapters, deterministic policy denial is considered first.
    if (shouldInvokeJudge(source)) {
      const verdict = await invokeJudge(source, ctx.signal);
      if (verdict && !verdict.safe) return { block: true, reason: verdict.reasoning };
    }
    setJudgeVerdict(event.toolCallId, { safe: true, reasoning: "Safety policy passed" });
  });

  pi.registerTool({
    name: "bash",
    label: "Bash",
    description: "Execute a bash command.",
    parameters: Type.Object({ command: Type.String(), timeout: Type.Optional(Type.Number()) }),
    async execute(toolCallId, params, signal, onUpdate, ctx) {
      return createBashTool(ctx.cwd).execute(toolCallId, params, signal, onUpdate, ctx);
    },
    renderCall(args, theme, context) {
      const container = new Container();
      const verdict = getJudgeVerdict(context.toolCallId);
      if (verdict && !verdict.safe) container.addChild(new Text(theme.italic(verdict.reasoning), 0, 0));
      container.addChild(new Text(theme.fg("toolTitle", theme.bold(`$ ${args.command || "..."}`)), 0, 0));
      return container;
    },
  });
}

/** Reconstruct branch-local settings, accepting only entries emitted by this adapter. */
export function resolvePiSessionSettings(entries: readonly unknown[], configured: PiAdapterConfig): PiSessionSettings {
  let settings: PiSessionSettings = { autoApprove: configured.autoApprove, judgeModel: configured.judgeModel };
  for (const entry of entries) {
    if (!isPiSettingsEntry(entry)) continue;
    settings = {
      autoApprove: entry.data.autoApprove,
      judgeModel: entry.data.judgeModel === null ? undefined : entry.data.judgeModel,
    };
  }
  return settings;
}

export default function (pi: ExtensionAPI) {
  return createPiExtension(pi);
}

function policyReason(result: BashPolicyEvaluation, fallback: string): string {
  const trace = result.traces.find((value) => value.decision.kind === "deny");
  return trace?.decision.reason?.map((part) => part.kind === "literal" ? part.value : String(part.value)).join("") ?? fallback;
}

function policyFailureReason(error: unknown): string {
  return error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
}

function isPiSettingsEntry(entry: unknown): entry is { readonly type: "custom"; readonly customType: typeof PI_SETTINGS_ENTRY; readonly data: PiSessionSettingsEntry } {
  if (typeof entry !== "object" || entry === null) return false;
  const record = entry as Record<string, unknown>;
  if (record.type !== "custom" || record.customType !== PI_SETTINGS_ENTRY || typeof record.data !== "object" || record.data === null) return false;
  const data = record.data as Record<string, unknown>;
  return typeof data.autoApprove === "boolean" && (typeof data.judgeModel === "string" || data.judgeModel === null);
}

function sessionEntries(ctx: ExtensionContext): readonly unknown[] {
  const sessionManager = ctx.sessionManager as { getBranch?: () => readonly unknown[] } | undefined;
  return sessionManager?.getBranch?.() ?? [];
}

async function buildJudgeProvider(
  configured: string | undefined,
  active: Model<any> | undefined,
  registry: { getAvailable(): Model<any>[]; getAll(): Model<any>[] } | undefined,
): Promise<JudgeProvider | null> {
  const runtime = (registry as { runtime?: ModelRuntimeAccess } | undefined)?.runtime;
  if (!runtime || !registry) return null;
  const model = resolveJudgeModel(configured, availableJudgeModels(registry), active);
  if (!model) return null;
  return createCompletionJudge(async (systemPrompt, userPrompt, signal) => {
    const response = await runtime.completeSimple(
      model,
      { systemPrompt, messages: [{ role: "user", content: userPrompt, timestamp: Date.now() }] },
      { maxTokens: 256, temperature: 0, signal, maxRetries: 0 },
    );
    if (response.stopReason === "error") throw new Error(response.errorMessage ?? "Judge request failed");
    return response.content
      .filter((block): block is { type: "text"; text: string } => block.type === "text")
      .map((block) => block.text)
      .join("");
  });
}

function availableJudgeModels(registry: { getAvailable(): Model<any>[]; getAll(): Model<any>[] } | undefined): Model<any>[] {
  if (!registry) return [];
  const models = registry.getAvailable();
  return (models.length > 0 ? models : registry.getAll()).slice().sort((left, right) => modelKey(left).localeCompare(modelKey(right)));
}

function resolveJudgeModel(configured: string | undefined, models: Model<any>[], active: Model<any> | undefined): Model<any> | undefined {
  if (!configured) return active;
  return models.find((model) => modelKey(model) === configured)
    ?? models.find((model) => model.provider === active?.provider && model.id === configured)
    ?? models.find((model) => model.id === configured);
}

function modelKey(model: Model<any>): string {
  return `${model.provider}/${model.id}`;
}
