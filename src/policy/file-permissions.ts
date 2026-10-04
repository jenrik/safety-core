import { posix } from "node:path";
import type { BashPolicyEvaluation } from "../authorization.js";
import type { SourceSpan } from "../bash/cst.js";
import type { NormalizedRedirect } from "../bash/expand.js";
import type { BashPolicyEvent } from "./types.js";

export type HarnessFilePermission = "allow" | "deny" | "ask" | "defer";

/** No argv-derived effects: these requests describe shell-owned opens only. */
export interface HarnessFileAccessRequest {
  readonly operation: "read" | "write";
  readonly effect: "read" | "truncate" | "append" | "read-write";
  /** Absolute shell spelling; harness adapters apply their lexical path rules. */
  readonly path: string | null;
  readonly cwd: string | null;
  readonly span: SourceSpan;
  readonly reason?: "unknown-path" | "unknown-cwd" | "special-file";
}

/** Adapters check existing permissions; implementations must not prompt. */
export interface HarnessFilePermissions {
  check(request: HarnessFileAccessRequest): HarnessFilePermission | Promise<HarnessFilePermission>;
}

export interface HarnessFilePermissionCheck {
  readonly request: HarnessFileAccessRequest;
  readonly decision: "allow" | "deny" | "defer";
}

export function shellFileAccesses(events: readonly BashPolicyEvent[]): readonly HarnessFileAccessRequest[] {
  const requests: HarnessFileAccessRequest[] = [];
  for (const event of events) {
    if (event.kind !== "invocation") continue;
    for (const redirect of event.ownRedirects ?? event.redirects) {
      if (!["input", "output", "append", "read-write"].includes(redirect.kind)) continue;
      // A process-substitution connection is not a user-file access request.
      if (redirect.target?.kind === "unknown" && redirect.target.reason.kind === "process-substitution") continue;
      const target = redirect.target?.kind === "known" ? redirect.target.value : null;
      const cwd = event.cwd ?? null;
      const path =
        target !== null && target.length > 0 && !target.includes("\0")
          ? target.startsWith("/")
            ? target
            : cwd === null
              ? null
              : `${cwd.replace(/\/$/, "")}/${target}`
          : null;
      const lexicalPath = path === null ? null : posix.normalize(path);
      // /dev/null is a supported file-permission target, not an exemption.
      const special =
        lexicalPath !== null && /^\/(?:dev|proc|sys)(?:\/|$)/.test(lexicalPath) && lexicalPath !== "/dev/null";
      const common = {
        path: special ? null : path,
        cwd,
        span: redirect.span ?? event.span,
        ...(special
          ? { reason: "special-file" as const }
          : path === null
            ? {
                reason:
                  target === null || target.length === 0 || target.includes("\0")
                    ? ("unknown-path" as const)
                    : ("unknown-cwd" as const),
              }
            : {}),
      };
      const effect =
        redirect.kind === "input"
          ? "read"
          : redirect.kind === "append"
            ? "append"
            : redirect.kind === "read-write"
              ? "read-write"
              : "truncate";
      if (redirect.kind === "input" || redirect.kind === "read-write")
        requests.push(Object.freeze({ ...common, operation: "read", effect }));
      if (redirect.kind !== "input") requests.push(Object.freeze({ ...common, operation: "write", effect }));
    }
  }
  return Object.freeze(requests);
}

/** Omitted redirection semantics cannot be repaired by a broad command allow. */
export function redirectIsUnmodeled(redirect: NormalizedRedirect): boolean {
  if (redirect.descriptor === null || redirect.kind === "unsupported" || redirect.kind === "here-document") return true;
  if (redirect.kind === "duplicate")
    return (
      redirect.target?.kind !== "known" ||
      !/^\d+$/.test(redirect.target.value) ||
      !Number.isSafeInteger(Number(redirect.target.value))
    );
  return redirect.kind === "here-string" && redirect.content === null;
}

/** Resolve file requirements separately from pure command-policy evaluation. */
export async function checkBashFilePermissions(
  evaluation: BashPolicyEvaluation,
  permissions?: HarnessFilePermissions,
): Promise<BashPolicyEvaluation> {
  const commandDecision = evaluation.commandDecision ?? evaluation.decision;
  if (commandDecision === "deny") return evaluation;
  const requests = evaluation.fileAccesses ?? shellFileAccesses(evaluation.events);
  const checks: HarnessFilePermissionCheck[] = [];
  for (const request of requests) {
    let decision: HarnessFilePermission = "defer";
    if (request.path !== null && permissions) {
      try {
        decision = await permissions.check(request);
      } catch {
        decision = "defer";
      }
    }
    checks.push(Object.freeze({ request, decision: decision === "allow" || decision === "deny" ? decision : "defer" }));
  }
  return Object.freeze({
    ...evaluation,
    commandDecision,
    fileAccesses: requests,
    filePermissionChecks: Object.freeze(checks),
    decision: combineBashPermissionVerdicts([commandDecision, ...checks.map((check) => check.decision)]),
  });
}

/** Most restrictive verdict across the total command and each required access. */
export function combineBashPermissionVerdicts(
  verdicts: readonly ("allow" | "deny" | "defer")[],
): "allow" | "deny" | "defer" {
  return verdicts.includes("deny") ? "deny" : verdicts.includes("defer") ? "defer" : "allow";
}
