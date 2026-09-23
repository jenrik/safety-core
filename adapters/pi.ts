import { createBashTool } from "@earendil-works/pi-coding-agent";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Container, Text } from "@earendil-works/pi-tui";
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
  setJudgeVerdict,
  getJudgeVerdict,
  invokeJudge,
  shouldInvokeJudge,
  type BashPolicyEvaluation,
  type LoadedPolicyRuntime,
  type ExecutableFilesystem,
} from "../src/index.js";

export interface PiExtensionDependencies {
  readonly runtime?: Promise<LoadedPolicyRuntime>;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: (runtime: LoadedPolicyRuntime, source: string, context?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem }) => BashPolicyEvaluation;
  readonly executableFilesystem?: ExecutableFilesystem;
}

/** Pi loads one policy set for the extension lifetime and never reloads it. */
export function createPiExtension(pi: ExtensionAPI, dependencies: PiExtensionDependencies = {}) {
  const parserReady = initBashParser(discoverWasmDir(import.meta.url));
  void parserReady.catch(() => {});
  let runtimeReady = dependencies.runtime;
  let poisoned: string | undefined;
  const ensureRuntime = (cwd: string) => {
    runtimeReady ??= (dependencies.loadRuntime ?? loadPolicyRuntime)(cwd);
    return runtimeReady;
  };
  const executableFilesystem = dependencies.executableFilesystem ?? nodeExecutableFilesystem;
  const evaluate = dependencies.evaluatePolicies ?? ((runtime, source, context) => evaluateLoadedPolicies(runtime, source, completePolicyInitialEnvironment(process.env), context));

  pi.on("session_start", async (_event, ctx) => {
    try {
      await parserReady;
      await ensureRuntime(ctx.cwd);
    } catch (error) {
      poisoned = policyFailureReason(error);
      throw new Error(poisoned);
    }
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
    if (result.decision === "defer") {
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
