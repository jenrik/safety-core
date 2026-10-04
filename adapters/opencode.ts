import { resolve } from "node:path";
import type { Hooks, PluginInput } from "@opencode-ai/plugin";
import { redactOpenCodeToolResult } from "../src/redact/opencode.js";

// This adapter targets only the OpenCode v1 plugin API. Keep OpenCode v2
// compatibility in adapters/opencode-v2.ts so either API can evolve independently.
import {
  type BashPolicyEvaluation,
  checkBashFilePermissions,
  checkWebfetchUrl,
  completePolicyInitialEnvironment,
  createAnthropicJudge,
  createOpenAIJudge,
  createOpenCodeBashPreflights,
  createOpenCodeFilePermissions,
  createPolicyRuntimeReloader,
  type ExecutableFilesystem,
  evaluateLoadedPolicies,
  type HarnessFilePermissions,
  initBundledBashParser,
  invokeJudge,
  isSecretPath,
  type LoadedPolicyRuntime,
  loadPolicyRuntime,
  nodeExecutableFilesystem,
  OPENCODE_POLICY_RELOAD_COMMAND,
  type OpenCodeFilePermissionContext,
  type OpenCodePermissionClient,
  openCodeBashPermissionStatus,
  SECRET_BLOCK_MESSAGE,
  setJudgeProvider,
  shouldInvokeJudge,
} from "@safety-core/core";

const OPENCODE_V1_PLUGIN_ID = "safety-core.policy-reload";

type OpenCodePermissionAskedEvent = {
  readonly type: "permission.asked";
  readonly properties: {
    readonly permission: string;
    readonly id: string;
    readonly sessionID: string;
    readonly tool?: { readonly callID?: string };
  };
};

type OpenCodeEvent = Parameters<NonNullable<Hooks["event"]>>[0]["event"] | OpenCodePermissionAskedEvent;

type OpenCodePermissionReplyClient = {
  readonly permission?: {
    reply(options: {
      directory?: string;
      requestID: string;
      reply: "once" | "reject";
      message?: string;
    }): Promise<unknown>;
  };
};

type PolicyEvaluator = (
  runtime: LoadedPolicyRuntime,
  source: string,
  context?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem },
) => BashPolicyEvaluation;

export interface OpenCodePluginDependencies {
  readonly runtime?: LoadedPolicyRuntime;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: PolicyEvaluator;
  readonly executableFilesystem?: ExecutableFilesystem;
  readonly filePermissions?: (context: OpenCodeFilePermissionContext) => HarnessFilePermissions;
}

export async function createOpenCodePlugin(
  dependencies: OpenCodePluginDependencies = {},
  client?: PluginInput["client"],
  directory?: string,
  worktree?: string,
) {
  await initBundledBashParser();
  const cwd = directory ?? process.cwd();
  const runtime = createPolicyRuntimeReloader(
    dependencies.loadRuntime ?? loadPolicyRuntime,
    dependencies.runtime === undefined ? undefined : Promise.resolve(dependencies.runtime),
  );
  await runtime.ensure(cwd);
  const executableFilesystem = dependencies.executableFilesystem ?? nodeExecutableFilesystem;
  const evaluate =
    dependencies.evaluatePolicies ??
    ((loaded, source, context) =>
      evaluateLoadedPolicies(loaded, source, completePolicyInitialEnvironment(process.env), context));
  const preflights = createOpenCodeBashPreflights();
  let poisoned: string | undefined;
  setJudgeProvider(buildJudgeProvider());

  const evaluateCommand = async (source: string, input: Record<string, unknown> = {}, workdir = cwd) => {
    const context: OpenCodeFilePermissionContext = {
      directory: cwd,
      ...(worktree === undefined ? {} : { worktree }),
      ...(typeof input.sessionID === "string" ? { sessionID: input.sessionID } : {}),
      ...(typeof input.callID === "string" ? { callID: input.callID } : {}),
    };
    return checkBashFilePermissions(
      evaluate(runtime.current()!, source, { cwd: workdir, executableFilesystem }),
      dependencies.filePermissions?.(context) ??
        createOpenCodeFilePermissions(client as unknown as OpenCodePermissionClient, context),
    );
  };
  const poison = (error: unknown) => {
    const reason = error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
    poisoned = reason;
    preflights.clear();
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
      const workdir = typeof args.workdir === "string" ? resolve(cwd, args.workdir) : cwd;
      const existingPoison = poisoned;
      if (existingPoison) throw new Error(existingPoison);
      const token = preflights.begin(input as unknown as Record<string, unknown>, source, workdir, args);
      let result: BashPolicyEvaluation;
      try {
        result = await evaluateCommand(source, input as unknown as Record<string, unknown>, workdir);
      } catch (error) {
        preflights.discard(token);
        throw new Error(poison(error));
      }
      if (result.decision === "deny") {
        preflights.discard(token);
        throw new Error(blockReason(result));
      }
      // Deterministic denial is resolved before judge invocation.
      try {
        if (shouldInvokeJudge(source)) {
          const verdict = await invokeJudge(source);
          if (verdict && !verdict.safe) throw new Error(`Blocked by safety policy: ${verdict.reasoning}`);
        }
      } catch (error) {
        preflights.discard(token);
        throw error;
      }
      preflights.complete(token, result);
    },
    "permission.ask": async (input, output) => {
      if (input.type !== "bash") return;
      const existingPoison = poisoned;
      if (existingPoison) {
        output.status = "deny";
        return;
      }
      output.status = openCodeBashPermissionStatus(
        preflights.get(input as unknown as Record<string, unknown>),
        output.status,
      );
    },
    event: async ({ event }: { event: OpenCodeEvent }) => {
      if (event.type === "tui.command.execute" && event.properties.command === OPENCODE_POLICY_RELOAD_COMMAND) {
        preflights.clear();
        try {
          await runtime.reload(cwd);
          poisoned = undefined;
          notifyPolicyReload(client, cwd, "Safety policies reloaded", "success");
        } catch (error) {
          // Keep the known-good runtime active when the replacement is invalid.
          notifyPolicyReload(
            client,
            cwd,
            error instanceof Error ? `Safety policy reload failed: ${error.message}` : "Safety policy reload failed",
            "error",
          );
        }
        return;
      }
      if (
        event.type === "message.part.updated" &&
        event.properties.part.type === "tool" &&
        ["completed", "error"].includes(event.properties.part.state.status)
      ) {
        preflights.finish(
          event.properties.part as unknown as Record<string, unknown>,
          event.properties.part.state.input,
        );
        return;
      }
      if (event.type === "session.deleted") {
        preflights.clearSession(event.properties.info.id);
        return;
      }
      if (!client || event.type !== "permission.asked" || event.properties.permission !== "bash") return;
      const permission = (client as unknown as OpenCodePermissionReplyClient).permission;
      if (!permission) return;
      const existingPoison = poisoned;
      if (existingPoison) {
        await permission.reply({
          ...replyDirectory(directory),
          requestID: event.properties.id,
          reply: "reject",
          message: existingPoison,
        });
        return;
      }
      const tool = event.properties.tool;
      const preflight = preflights.get({ sessionID: event.properties.sessionID, callID: tool?.callID });
      if (!preflight || preflight.kind !== "complete") return;
      const result = preflight.evaluation;
      if (result.decision === "allow") {
        await permission.reply({ ...replyDirectory(directory), requestID: event.properties.id, reply: "once" });
      } else if (result.decision === "deny") {
        await permission.reply({
          ...replyDirectory(directory),
          requestID: event.properties.id,
          reply: "reject",
          message: blockReason(result),
        });
      }
    },
    "tool.execute.after": async (input, output) => {
      if (input.tool === "bash") preflights.finish(input as unknown as Record<string, unknown>, input.args);
      await redactOpenCodeToolResult(output, runtime.current()?.config.redact);
    },
  } satisfies Hooks;
}

export default {
  id: OPENCODE_V1_PLUGIN_ID,
  server: async (input?: PluginInput) => createOpenCodePlugin({}, input?.client, input?.directory, input?.worktree),
};

export function blockReason(result: BashPolicyEvaluation): string {
  if (result.filePermissionChecks?.some((check) => check.decision === "deny"))
    return "Blocked by safety policy: harness denied shell redirect file access";
  const denial = result.traces.find((trace) => trace.decision.kind === "deny");
  const reason =
    (denial?.decision.kind === "deny"
      ? denial.decision.reason?.map((part) => (part.kind === "literal" ? part.value : String(part.value))).join("")
      : undefined) ?? "Bash policy denied this command";
  return `Blocked by safety policy: ${reason}`;
}

function buildJudgeProvider() {
  if (process.env.ANTHROPIC_API_KEY) return createAnthropicJudge({ apiKey: process.env.ANTHROPIC_API_KEY });
  if (process.env.OPENAI_API_KEY) return createOpenAIJudge({ apiKey: process.env.OPENAI_API_KEY });
  return null;
}

function replyDirectory(directory: string | undefined): { readonly directory?: string } {
  return directory === undefined ? {} : { directory };
}

function notifyPolicyReload(
  client: PluginInput["client"] | undefined,
  directory: string,
  message: string,
  variant: "success" | "error",
): void {
  const tui = (
    client as unknown as
      | {
          tui?: {
            showToast?: (options: {
              query: { directory: string };
              body: { title: string; message: string; variant: string };
            }) => Promise<unknown>;
          };
        }
      | undefined
  )?.tui;
  try {
    void Promise.resolve(
      tui?.showToast?.({
        query: { directory },
        body: { title: "Safety policy reload", message, variant },
      }),
    ).catch(() => {});
  } catch {
    // A toast failure must not change the policy decision path.
  }
}
