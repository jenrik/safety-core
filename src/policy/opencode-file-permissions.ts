import { dirname, relative, resolve } from "node:path";
import type { HarnessFilePermissions, HarnessFilePermission } from "./file-permissions.js";

export interface OpenCodePermissionRule {
  readonly permission: string;
  readonly pattern: string;
  readonly action: "allow" | "ask" | "deny";
}

/** Only read-only SDK endpoints are used. Unsupported response shapes defer. */
export interface OpenCodePermissionClient {
  readonly app?: { agents(options: unknown): Promise<unknown> };
  readonly session?: {
    get(options: unknown): Promise<unknown>;
    messages(options: unknown): Promise<unknown>;
  };
}

export interface OpenCodeFilePermissionContext {
  readonly sessionID?: string;
  readonly callID?: string;
  readonly directory: string;
  readonly worktree?: string;
}

/**
 * Mirror OpenCode's compiled-rule evaluation, not raw-config/default merging.
 * Upstream: packages/core/src/util/wildcard.ts and permission.ts (dev,
 * 2026-10-01). Read native agent rules, including defaults, from app.agents.
 * Configured ask deliberately remains defer; this does not manufacture saved
 * approvals or create a permission request to discover the answer.
 */
export function evaluateOpenCodePermission(
  permission: string,
  pattern: string,
  rules: readonly OpenCodePermissionRule[],
): HarnessFilePermission {
  return (
    rules.findLast((rule) => nativeWildcard(permission, rule.permission) && nativeWildcard(pattern, rule.pattern))
      ?.action ?? "ask"
  );
}

function nativeWildcard(input: string, pattern: string): boolean {
  let escaped = pattern
    .replaceAll("\\", "/")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  if (escaped.endsWith(" .*")) escaped = escaped.slice(0, -3) + "( .*)?";
  return new RegExp(`^${escaped}$`, process.platform === "win32" ? "si" : "s").test(input.replaceAll("\\", "/"));
}

export function createOpenCodeFilePermissions(
  client: OpenCodePermissionClient | undefined,
  context: OpenCodeFilePermissionContext,
): HarnessFilePermissions {
  let rules: Promise<readonly OpenCodePermissionRule[] | undefined> | undefined;
  return Object.freeze({
    async check(request) {
      if (
        request.path === null ||
        !absoluteLexicalPath(request.path) ||
        !absoluteLexicalPath(context.directory) ||
        (context.worktree !== undefined && !absoluteLexicalPath(context.worktree))
      )
        return "defer";
      rules ??= nativeRules(client, context);
      const resolvedRules = await rules;
      if (!resolvedRules) return "defer";
      // File rules authorize lexical path identities, just as native tool
      // resources do. Resolving symlinks here would observe only a snapshot,
      // not bind the later shell open to the observed target.
      const path = resolve(request.path);
      const directory = resolve(context.directory);
      const worktree = context.worktree === undefined ? undefined : resolve(context.worktree);
      const root = worktree ?? directory;
      const permission = request.operation === "read" ? "read" : "edit";
      // Native read/edit patterns are worktree-relative. A root worktree is
      // still the resource base, but OpenCode excludes it from containment.
      const decisions: HarnessFilePermission[] = [
        evaluateOpenCodePermission(permission, relative(root, path), resolvedRules),
      ];
      if (!contains(directory, path) && !(worktree && worktree !== "/" && contains(worktree, path))) {
        decisions.push(evaluateOpenCodePermission("external_directory", `${dirname(path)}/*`, resolvedRules));
      }
      return decisions.includes("deny")
        ? "deny"
        : decisions.every((decision) => decision === "allow")
          ? "allow"
          : "defer";
    },
  });
}

async function nativeRules(
  client: OpenCodePermissionClient | undefined,
  context: OpenCodeFilePermissionContext,
): Promise<readonly OpenCodePermissionRule[] | undefined> {
  if (!client?.app || !client.session || !context.sessionID || !context.callID) return undefined;
  const options = {
    path: { id: context.sessionID },
    query: { directory: context.directory },
    sessionID: context.sessionID,
    directory: context.directory,
  };
  try {
    const [agents, messages, session] = await Promise.all([
      client.app.agents({ query: { directory: context.directory }, directory: context.directory }),
      client.session.messages(options),
      client.session.get(options),
    ]);
    const agentList = responseData(agents);
    const messageList = responseData(messages);
    const sessionInfo = responseData(session);
    if (!Array.isArray(agentList) || !Array.isArray(messageList) || !isRecord(sessionInfo)) return undefined;
    const matches = messageList.filter(
      (message) =>
        isRecord(message) &&
        isRecord(message.info) &&
        message.info.role === "assistant" &&
        Array.isArray(message.parts) &&
        message.parts.some((part: unknown) => isRecord(part) && part.type === "tool" && part.callID === context.callID),
    );
    if (matches.length !== 1) return undefined;
    const info = matches[0].info;
    const agent = agentList.find((candidate) => isRecord(candidate) && candidate.name === info.agent);
    if (!isRecord(agent) || !isRuleset(agent.permission)) return undefined;
    // A session-specific ruleset is appended by native OpenCode. If the host
    // exposes an unrecognized shape, its effect is unknown, not absent.
    if (sessionInfo.permission !== undefined && !isRuleset(sessionInfo.permission)) return undefined;
    return Object.freeze([...agent.permission, ...(sessionInfo.permission ?? [])]);
  } catch {
    return undefined;
  }
}

function responseData(value: unknown): unknown {
  return isRecord(value) && !value.error ? value.data : undefined;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isRuleset(value: unknown): value is readonly OpenCodePermissionRule[] {
  return (
    Array.isArray(value) &&
    value.every(
      (rule) =>
        isRecord(rule) &&
        typeof rule.permission === "string" &&
        typeof rule.pattern === "string" &&
        ["allow", "ask", "deny"].includes(rule.action),
    )
  );
}

function contains(root: string, path: string): boolean {
  const suffix = relative(root, path);
  return suffix === "" || (suffix !== ".." && !suffix.startsWith("../") && !suffix.startsWith("/"));
}

function absoluteLexicalPath(path: string): boolean {
  return path.startsWith("/") && !path.includes("\0");
}
