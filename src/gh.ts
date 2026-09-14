// gh-api compatibility adapter backed by the stateful Bash authorization walker.
// TODO: Fold this repeated whole-command compatibility evaluation into the
// configured, single-pass core Bash evaluator.

import { analyzeBashAuthorization, type BashAuthorizationContext } from "./authorization.js";
import { ghApiHandler } from "./bash/handlers/command-gh-api.js";

export type GhApiDecision =
  | { kind: "allow"; reason: string }
  | { kind: "deny"; reason: string }
  | { kind: "defer" }
  | { kind: "ignore" };

/** Analyze every resolved gh api invocation, allowing only an all-safe Bash call. */
export function analyzeGhApiCommand(command: string, context: BashAuthorizationContext = {}): GhApiDecision {
  const analysis = analyzeBashAuthorization({ source: command, handlers: [ghApiHandler], ...context });
  const policy = analysis.policies.find((evidence) => evidence.name === "gh-api");
  if (!policy || policy.name !== "gh-api") return { kind: "ignore" };
  if (policy.decision === "deny") return { kind: "deny", reason: policy.reason ?? "gh api is not read-only" };
  if (policy.decision === "allow" && analysis.verdict.kind === "allow") {
    return { kind: "allow", reason: policy.reason ?? "gh api auto-allowed (GET, no parameters)" };
  }
  return { kind: "defer" };
}
