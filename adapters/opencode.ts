import type { Plugin, PluginInput } from "@opencode-ai/plugin";

// This adapter targets only the OpenCode v1 plugin API. Keep OpenCode v2
// compatibility in adapters/opencode-v2.ts so either API can evolve independently.
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
  OPENCODE_POLICY_RELOAD_COMMAND,
  setJudgeProvider,
  invokeJudge,
  shouldInvokeJudge,
  createAnthropicJudge,
  createOpenAIJudge,
  type LoadedPolicyRuntime,
  type BashPolicyEvaluation,
  type ExecutableFilesystem,
} from "../src/index.js";

type PolicyEvaluator = (runtime: LoadedPolicyRuntime, source: string, context?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem }) => BashPolicyEvaluation;

export interface OpenCodePluginDependencies {
  readonly runtime?: LoadedPolicyRuntime;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: PolicyEvaluator;
  readonly executableFilesystem?: ExecutableFilesystem;
}

export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
) {
  await initBashParser(discoverWasmDir(import.meta.url));
  const cwd = directory ?? process.cwd();
  const runtime = createPolicyRuntimeReloader(
    dependencies.loadRuntime ?? loadPolicyRuntime,
    dependencies.runtime === undefined ? undefined : Promise.resolve(dependencies.runtime),
  );
  await runtime.ensure(cwd);
  const executableFilesystem = dependencies.executableFilesystem ?? nodeExecutableFilesystem;
  const evaluate = dependencies.evaluatePolicies ?? ((loaded, source, context) => evaluateLoadedPolicies(loaded, source, completePolicyInitialEnvironment(process.env), context));
  const results = new Map<string, BashPolicyEvaluation>();
  let poisoned: string | undefined;
  setJudgeProvider(buildJudgeProvider());

  const evaluateCommand = (source: string) => evaluate(runtime.current()!, source, { cwd, executableFilesystem });
  const cacheKey = (value: Record<string, unknown>, source: string) =>
    typeof value.sessionID === "string" && typeof value.callID === "string" ? `${value.sessionID}\u0000${value.callID}\u0000${source}` : undefined;
  const poison = (error: unknown) => {
    const reason = error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
    poisoned = reason;
    return reason;
  };

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
      const existingPoison = poisoned;
      if (existingPoison) throw new Error(existingPoison);
      let result: BashPolicyEvaluation;
      try {
        result = evaluateCommand(source);
      } catch (error) {
        throw new Error(poison(error));
      }
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
      const existingPoison = poisoned;
      if (existingPoison) {
        output.status = "deny";
        return;
      }
      let result: BashPolicyEvaluation;
      try {
        result = evaluateCommand(source);
      } catch (error) {
        poison(error);
        output.status = "deny";
        return;
      }
      if (result.decision === "allow" || result.decision === "deny") output.status = result.decision;
    },
    event: async ({ event }) => {
      if (event.type === "tui.command.execute" && event.properties.command === OPENCODE_POLICY_RELOAD_COMMAND) {
        try {
          await runtime.reload(cwd);
          poisoned = undefined;
          notifyPolicyReload(client, cwd, "Safety policies reloaded", "success");
        } catch (error) {
          // Keep the known-good runtime active when the replacement is invalid.
          notifyPolicyReload(client, cwd, error instanceof Error ? `Safety policy reload failed: ${error.message}` : "Safety policy reload failed", "error");
        }
        return;
      }
      if (!client || event.type !== "permission.asked" || event.properties.permission !== "bash") return;
      const source = event.properties.patterns.join(" && ");
      const existingPoison = poisoned;
      if (existingPoison) {
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "reject", message: existingPoison });
        return;
      }
      let result: BashPolicyEvaluation;
      try {
        result = evaluateCommand(source);
      } catch (error) {
        const reason = poison(error);
        await client.permission.reply({ directory, requestID: event.properties.id, reply: "reject", message: reason });
        return;
      }
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

function notifyPolicyReload(
  client: PluginInput["client"] | undefined,
  directory: string,
  message: string,
  variant: "success" | "error",
): void {
  const tui = (client as unknown as { tui?: { showToast?: (options: { query: { directory: string }; body: { title: string; message: string; variant: string } }) => Promise<unknown> } } | undefined)?.tui;
  try {
    void Promise.resolve(tui?.showToast?.({
      query: { directory },
      body: { title: "Safety policy reload", message, variant },
    })).catch(() => {});
  } catch {
    // A toast failure must not change the policy decision path.
  }
}
