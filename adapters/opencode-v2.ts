import { resolve } from "node:path";
import { redactOpenCodeToolResult } from "../src/redact/opencode.js";

import {
  type BashPolicyEvaluation,
  checkBashFilePermissions,
  checkWebfetchUrl,
  completePolicyInitialEnvironment,
  createAnthropicJudge,
  createOpenCodeBashPreflights,
  createOpenCodeFilePermissions,
  createOpenAIJudge,
  createPolicyRuntimeReloader,
  discoverWasmDir,
  type ExecutableFilesystem,
  evaluateLoadedPolicies,
  forwardPermissionPrompt,
  type HarnessFilePermissions,
  initBashParser,
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

/** Dependencies are intentionally independent of the OpenCode v1 client API. */
export interface OpenCodeV2PluginDependencies {
  readonly runtime?: LoadedPolicyRuntime;
  readonly loadRuntime?: (cwd: string) => Promise<LoadedPolicyRuntime>;
  readonly evaluatePolicies?: (
    runtime: LoadedPolicyRuntime,
    source: string,
    context?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem },
  ) => BashPolicyEvaluation;
  readonly executableFilesystem?: ExecutableFilesystem;
  readonly filePermissions?: (context: OpenCodeFilePermissionContext) => HarnessFilePermissions;
}

export type OpenCodeV2ToolEvent = {
  readonly tool: string;
  readonly sessionID: string;
  readonly id: string;
  readonly input: unknown;
};

/** Tool-result payload the harness passes to the `execute.after` hook. */
export type OpenCodeV2ToolResult = {
  readonly title: string;
  readonly output: string;
  readonly metadata: unknown;
  readonly attachments?: unknown;
};

export type OpenCodeV2PermissionEvent = {
  readonly action: string;
  readonly sessionID: string;
  readonly source?: { readonly type?: string; readonly id?: string };
  effect: "allow" | "ask" | "deny";
};

type OpenCodeV2Registration = { dispose(): Promise<void> };

export type OpenCodeV2Context = {
  readonly location: { readonly directory: string; readonly worktree?: string };
  readonly agent: { list(): Promise<unknown> };
  readonly session: {
    get(input: { readonly sessionID: string }): Promise<unknown>;
    context(input: { readonly sessionID: string }): Promise<unknown>;
  };
  readonly command: {
    transform(
      callback: (editor: { add(definition: OpenCodeV2Command): void }) => void,
    ): Promise<OpenCodeV2Registration>;
  };
  readonly tool: {
    hook(
      name: "execute.before" | "execute.after",
      callback: (event: OpenCodeV2ToolEvent, output?: OpenCodeV2ToolResult) => Promise<void>,
    ): Promise<unknown>;
  };
  readonly permission: {
    hook(name: "evaluate", callback: (event: OpenCodeV2PermissionEvent) => Promise<void>): Promise<unknown>;
  };
  readonly event: { subscribe(options: { readonly signal: AbortSignal }): AsyncIterable<unknown> };
};

type OpenCodeV2Command = {
  readonly name: string;
  readonly description?: string;
  readonly execute: (input: unknown) => Promise<void>;
};

export type OpenCodeV2PolicyRuntime = {
  before(event: OpenCodeV2ToolEvent): Promise<void>;
  after(event: OpenCodeV2ToolEvent, output?: unknown): Promise<void>;
  evaluatePermission(event: OpenCodeV2PermissionEvent): Promise<void>;
  reload(): Promise<void>;
  sessionDeleted(sessionID: string): void;
};

export function normalizeOpenCodeV2ToolName(tool: string): string {
  return tool === "shell" ? "bash" : tool;
}

/**
 * Build the V2 policy lifecycle directly from V2 tool and permission events.
 * This deliberately has no dependency on the V1 hook map or plugin client.
 */
export async function createOpenCodeV2PolicyRuntime(
  dependencies: OpenCodeV2PluginDependencies,
  context: Pick<OpenCodeV2Context, "location" | "agent" | "session">,
): Promise<OpenCodeV2PolicyRuntime> {
  await initBashParser(discoverWasmDir(import.meta.url));
  const cwd = context.location.directory;
  const runtime = createPolicyRuntimeReloader(
    dependencies.loadRuntime ?? loadPolicyRuntime,
    dependencies.runtime === undefined ? undefined : Promise.resolve(dependencies.runtime),
  );
  await runtime.ensure(cwd);
  const executableFilesystem = dependencies.executableFilesystem ?? nodeExecutableFilesystem;
  const evaluate =
    dependencies.evaluatePolicies ??
    ((
      loaded: LoadedPolicyRuntime,
      source: string,
      policyContext?: { readonly cwd?: string; readonly executableFilesystem?: ExecutableFilesystem },
    ) => evaluateLoadedPolicies(loaded, source, completePolicyInitialEnvironment(process.env), policyContext));
  const preflights = createOpenCodeBashPreflights();
  let poisoned: string | undefined;
  setJudgeProvider(buildJudgeProvider());

  const evaluateCommand = async (source: string, event: OpenCodeV2ToolEvent, workdir: string) => {
    const permissionContext: OpenCodeFilePermissionContext = {
      directory: cwd,
      ...(context.location.worktree === undefined ? {} : { worktree: context.location.worktree }),
      sessionID: event.sessionID,
      callID: event.id,
    };
    return checkBashFilePermissions(
      evaluate(runtime.current()!, source, { cwd: workdir, executableFilesystem }),
      dependencies.filePermissions?.(permissionContext) ??
        createOpenCodeFilePermissions(v2PermissionClient(context), permissionContext),
    );
  };
  const poison = (error: unknown) => {
    const reason = error instanceof Error ? `Safety policy failed: ${error.message}` : "Safety policy failed";
    poisoned = reason;
    preflights.clear();
    return reason;
  };

  return {
    async before(event) {
      const args = asRecord(event.input);
      const tool = normalizeOpenCodeV2ToolName(event.tool);
      if (tool === "read" && isSecretPath(String(args.filePath ?? args.file_path ?? args.path ?? "")))
        throw new Error(`Blocked by safety policy: ${SECRET_BLOCK_MESSAGE}`);
      if (tool === "webfetch") {
        const reason = checkWebfetchUrl(String(args.url ?? ""));
        if (reason) throw new Error(reason);
      }
      if (tool !== "bash") return;
      if (poisoned) throw new Error(poisoned);
      const source = String(args.command ?? "");
      const workdir = typeof args.workdir === "string" ? resolve(cwd, args.workdir) : cwd;
      const token = preflights.begin({ sessionID: event.sessionID, callID: event.id }, source, workdir, event.input);
      let result: BashPolicyEvaluation;
      try {
        result = await evaluateCommand(source, event, workdir);
      } catch (error) {
        preflights.discard(token);
        throw new Error(poison(error));
      }
      if (result.decision === "deny") {
        preflights.discard(token);
        throw new Error(blockReason(result));
      }
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
    async after(event, output) {
      if (normalizeOpenCodeV2ToolName(event.tool) === "bash")
        preflights.finish({ sessionID: event.sessionID, callID: event.id }, event.input);
      if (output !== undefined)
        await redactOpenCodeToolResult(output as OpenCodeV2ToolResult, runtime.current()?.config.redact);
    },
    async evaluatePermission(event) {
      if (event.action !== "shell" && event.action !== "bash") return;
      if (poisoned) {
        event.effect = "deny";
        return;
      }
      const callID = event.source?.type === "tool" ? event.source.id : undefined;
      const preflight = preflights.get({ sessionID: event.sessionID, callID });
      event.effect = openCodeBashPermissionStatus(preflight, event.effect);
      if (event.effect !== "ask" || preflight?.kind !== "complete" || preflight.evaluation.decision !== "defer") return;
      const approved = await forwardPermissionPrompt({
        title: "Safety permission required",
        message: `Nested OpenCode requires approval to execute:\n\n${preflight.source}\n\nAllow it once?`,
      });
      if (approved !== undefined) event.effect = approved ? "allow" : "deny";
    },
    async reload() {
      preflights.clear();
      try {
        await runtime.reload(cwd);
        poisoned = undefined;
      } catch {
        // Keep the known-good runtime active when replacement configuration is invalid.
      }
    },
    sessionDeleted(sessionID) {
      preflights.clearSession(sessionID);
    },
  };
}

/**
 * Compatibility test harness for the pre-V2 fixture suite. Production code
 * enters through `setup()` above; this does not import or delegate to the V1
 * adapter and translates fixture calls into the V2 event model locally.
 */
export async function createOpenCodeV2Plugin(
  dependencies: OpenCodeV2PluginDependencies = {},
  client?: unknown,
  directory = process.cwd(),
  worktree?: string,
) {
  const legacyClient = client as OpenCodePermissionClient | undefined;
  const context = {
    location: { directory, ...(worktree === undefined ? {} : { worktree }) },
    agent: {
      list: async () => responseData(await legacyClient?.app?.agents({ query: { directory }, directory })) ?? [],
    },
    session: {
      get: async ({ sessionID }: { sessionID: string }) =>
        responseData(
          await legacyClient?.session?.get({ path: { id: sessionID }, query: { directory }, sessionID, directory }),
        ) ?? {},
      context: async ({ sessionID }: { sessionID: string }) =>
        responseData(
          await legacyClient?.session?.messages({
            path: { id: sessionID },
            query: { directory },
            sessionID,
            directory,
          }),
        ) ?? [],
    },
  } satisfies Pick<OpenCodeV2Context, "location" | "agent" | "session">;
  const policy = await createOpenCodeV2PolicyRuntime(dependencies, context);
  return {
    "tool.execute.before": async (input: Record<string, unknown>, output: { readonly args: unknown }) =>
      policy.before({
        tool: String(input.tool ?? ""),
        sessionID: String(input.sessionID ?? ""),
        id: String(input.callID ?? ""),
        input: output.args,
      }),
    "tool.execute.after": async (input: Record<string, unknown>, output: unknown) =>
      policy.after(
        {
          tool: String(input.tool ?? ""),
          sessionID: String(input.sessionID ?? ""),
          id: String(input.callID ?? ""),
          input: input.args,
        },
        output,
      ),
    "permission.ask": async (input: Record<string, unknown>, output: { status: "allow" | "ask" | "deny" }) => {
      const event: OpenCodeV2PermissionEvent = {
        action: String(input.type ?? ""),
        sessionID: String(input.sessionID ?? ""),
        ...(typeof input.callID === "string" ? { source: { type: "tool", id: input.callID } } : {}),
        effect: output.status,
      };
      await policy.evaluatePermission(event);
      output.status = event.effect;
    },
    event: async ({ event }: { event: unknown }) => {
      const record = asRecord(event);
      if (
        record.type === "tui.command.execute" &&
        asRecord(record.properties).command === OPENCODE_POLICY_RELOAD_COMMAND
      )
        await policy.reload();
      if (record.type === "session.deleted") {
        const id = asRecord(asRecord(record.properties).info).id;
        if (typeof id === "string") policy.sessionDeleted(id);
      }
      if (record.type === "message.part.updated") {
        const part = asRecord(asRecord(record.properties).part);
        const state = asRecord(part.state);
        if (part.type === "tool" && (state.status === "completed" || state.status === "error"))
          policy.after({
            tool: "bash",
            sessionID: String(part.sessionID ?? ""),
            id: String(part.callID ?? ""),
            input: state.input,
          });
      }
    },
  };
}

export async function registerOpenCodeV2ReloadCommand(
  command: OpenCodeV2Context["command"],
  reloadPolicies: () => Promise<void>,
): Promise<OpenCodeV2Registration> {
  return command.transform((editor) => {
    editor.add({
      name: OPENCODE_POLICY_RELOAD_COMMAND,
      description: "Reload safety-core policies",
      execute: reloadPolicies,
    });
  });
}

export default {
  id: "safety-core",
  async setup(context: OpenCodeV2Context) {
    const policy = await createOpenCodeV2PolicyRuntime({}, context);
    const reloadCommand = await registerOpenCodeV2ReloadCommand(context.command, () => policy.reload());
    await context.tool.hook("execute.before", (event) => policy.before(event));
    await context.tool.hook("execute.after", async (event, output) => policy.after(event, output));
    await context.permission.hook("evaluate", (event) => policy.evaluatePermission(event));

    const events = new AbortController();
    void consumeEvents(context.event.subscribe({ signal: events.signal }), policy).catch(() => {});
    return async () => {
      events.abort();
      await reloadCommand.dispose();
    };
  },
};

async function consumeEvents(events: AsyncIterable<unknown>, policy: OpenCodeV2PolicyRuntime): Promise<void> {
  for await (const event of events) {
    const record = asRecord(event);
    if (record.type !== "session.deleted") continue;
    const properties = asRecord(record.properties);
    const info = asRecord(properties.info);
    if (typeof info.id === "string") policy.sessionDeleted(info.id);
  }
}

function v2PermissionClient(
  context: Pick<OpenCodeV2Context, "location" | "agent" | "session">,
): OpenCodePermissionClient {
  return {
    app: { agents: async () => ({ data: await context.agent.list() }) },
    session: {
      get: async (input) => ({
        data: await context.session.get({ sessionID: String(asRecord(input).sessionID ?? "") }),
      }),
      messages: async (input) => ({
        data: await context.session.context({ sessionID: String(asRecord(input).sessionID ?? "") }),
      }),
    },
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function responseData(value: unknown): unknown {
  const record = asRecord(value);
  return record.error ? undefined : record.data;
}

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
