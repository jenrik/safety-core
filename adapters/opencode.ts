import type { Plugin, PluginInput } from "@opencode-ai/plugin";

import {
  SECRET_BLOCK_MESSAGE,
  checkWebfetchUrl,
  discoverWasmDir,
  evaluateLoadedPolicies,
  initBashParser,
  isSecretPath,
  loadPolicyRuntime,
  policyInitialEnvironment,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type LoadedPolicyRuntime,
  type BashPolicyEvaluation,
} from "../src/index.js";

type PolicyEvaluator = (runtime: LoadedPolicyRuntime, source: string) => BashPolicyEvaluation;

export interface OpenCodePluginDependencies {
  readonly runtime?: LoadedPolicyRuntime;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: PolicyEvaluator;
}

/** Load once at plugin startup; a startup failure prevents the plugin from running. */
export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const runtime = dependencies.runtime ?? await (dependencies.loadRuntime ?? loadPolicyRuntime)(directory ?? process.cwd());
  const evaluate = dependencies.evaluatePolicies ?? ((loaded, source) => evaluateLoadedPolicies(loaded, source, policyInitialEnvironment(process.env)));
  const results = new Map<string, BashPolicyEvaluation>();
  setJudgeProvider(buildJudgeProvider());

  const evaluateCommand = (source: string) => evaluate(runtime, source);
  const cacheKey = (value: Record<string, unknown>, source: string) =>
    typeof value.sessionID === "string" && typeof value.callID === "string" ? `${value.sessionID}\u0000${value.callID}\u0000${source}` : undefined;

  return {
    "tool.execute.before": async (input, output) => {
      const args = output.args as Record<string, unknown>;
      if (input.tool === "read" && isSecretPath(String(args.filePath ?? args.file_path ?? args.path ?? ""))) {
        throw new Error(`Blocked by safety policy: ${SECRET_BLOCK_MESSAGE}`);
      }
      if (input.tool === "webfetch") {
        const reason = checkWebfetchUrl(String(args.url ?? ""));
        if (reason) throw new Error(reason);
      }
      if (input.tool !== "bash") return;
      const source = String(args.command ?? "");
      const result = evaluateCommand(source);
      if (result.decision === "deny") throw new Error(blockReason(result));
      // Deterministic policy denial is resolved before judge invocation.
      if (shouldInvokeJudge(source)) {
        const verdict = await invokeJudge(source);
        if (verdict && !verdict.safe) throw new Error(`Blocked by safety policy: ${verdict.reasoning}`);
      }
      const key = cacheKey(input as Record<string, unknown>, source);
      if (key) results.set(key, result);
    },
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;
      const source = Array.isArray(input.pattern) ? input.pattern.join(" && ") : input.pattern;
      if (!source) return;
      const result = evaluateCommand(source);
      if (result.decision === "allow" || result.decision === "deny") output.status = result.decision;
    },
    event: async ({ event }) => {
      if (!client || event.type !== "permission.asked" || event.properties.permission !== "bash") return;
      const source = event.properties.patterns.join(" && ");
      const result = evaluateCommand(source);
      if (result.decision === "allow") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "once" });
      } else if (result.decision === "deny") {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "reject", message: blockReason(result) });
      }
    },
    "tool.execute.after": async (input, _output) => {
      if (input.tool !== "bash") return;
      const source = String((input.args as Record<string, unknown>).command ?? "");
      const key = cacheKey(input as Record<string, unknown>, source);
      if (key) results.delete(key);
    },
  } satisfies Plugin;
}

export default async (input?: PluginInput) => createOpenCodePlugin({}, input?.client, input?.directory);

export function blockReason(result: BashPolicyEvaluation): string {
  const denial = result.traces.find((trace) => trace.decision.kind === "deny");
  const reason = denial?.decision.reason?.map((part) => part.kind === "literal" ? part.value : String(part.value)).join("") ?? "Bash policy denied this command";
  return `Blocked by safety policy: ${reason}`;
}

function buildJudgeProvider() {
  if (process.env.ANTHROPIC_API_KEY) return createAnthropicJudge({ apiKey: process.env.ANTHROPIC_API_KEY });
  if (process.env.OPENAI_API_KEY) return createOpenAIJudge({ apiKey: process.env.OPENAI_API_KEY });
  return null;
}
