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
  policyInitialEnvironment,
  setJudgeVerdict,
  getJudgeVerdict,
  invokeJudge,
  shouldInvokeJudge,
  type BashPolicyEvaluation,
  type LoadedPolicyRuntime,
} from "../src/index.js";

export interface PiExtensionDependencies {
  readonly runtime?: Promise<LoadedPolicyRuntime>;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: (runtime: LoadedPolicyRuntime, source: string) => BashPolicyEvaluation;
}

/** Pi loads one policy set for the extension lifetime and never reloads it. */
export function createPiExtension(pi: ExtensionAPI, dependencies: PiExtensionDependencies = {}) {
  const parserReady = initBashParser(discoverWasmDir(import.meta.url));
  void parserReady.catch(() => {});
  const runtimeReady = dependencies.runtime ?? (dependencies.loadRuntime ?? loadPolicyRuntime)(process.cwd());
  void runtimeReady.catch(() => {});
  const evaluate = dependencies.evaluatePolicies ?? ((runtime, source) => evaluateLoadedPolicies(runtime, source, policyInitialEnvironment(process.env)));

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
    let result: BashPolicyEvaluation;
    try {
      await parserReady;
      result = evaluate(await runtimeReady, source);
    } catch (error) {
      const reason = error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
      setJudgeVerdict(event.toolCallId, { safe: false, reasoning: reason });
      return { block: true, reason };
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
