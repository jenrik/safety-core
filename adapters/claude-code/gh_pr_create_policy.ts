// Claude Code hook: allow scoped native `gh pr create` and deny attempts that
// fall outside the shared ghPrCreate profile, including direct gh-api bypasses.

import {
  analyzeGhPrCreateAuthorization,
  analyzeGhPrCreateCommand,
  discoverWasmDir,
  initBashParser,
  loadBashAnalysisLimits,
  loadGhPrCreatePolicy,
  mapClaudeBashDecision,
} from "../../src/index.js";

import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const policy = loadGhPrCreatePolicy();
  if (!policy.enabled) return;

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  const context = bashAuthorizationContext();

  try {
    await initBashParser(discoverWasmDir(import.meta.url));
  } catch {
    const decision = analyzeGhPrCreateCommand(command, policy, context);
    if (decision.kind === "deny") emitDeny(decision.reason);
    return;
  }
  const analysis = analyzeGhPrCreateAuthorization(command, policy, context);
  if (mapClaudeBashDecision(analysis.verdict) === "allow") emitAllow("gh pr create auto-allowed for an allowlisted repository");
  if (mapClaudeBashDecision(analysis.verdict) === "deny") emitDeny(analysis.policies.find((evidence) => evidence.decision === "deny")?.reason
    ?? "Pull-request creation is blocked");
});

function bashAuthorizationContext() {
  return Object.freeze({
    limits: loadBashAnalysisLimits(),
    initialEnvironment: { kind: "unavailable" as const },
  });
}
