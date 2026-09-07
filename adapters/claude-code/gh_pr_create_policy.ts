// Claude Code hook: allow scoped native `gh pr create` and deny attempts that
// fall outside the shared ghPrCreate profile, including direct gh-api bypasses.

import {
  analyzeGhPrCreateCommand,
  discoverWasmDir,
  initBashParser,
  loadGhPrCreatePolicy,
} from "../../src/index.js";

import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const policy = loadGhPrCreatePolicy();
  if (!policy.enabled) return;

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";

  try {
    await initBashParser(discoverWasmDir(import.meta.url));
  } catch {
    const decision = analyzeGhPrCreateCommand(command, policy);
    if (decision.kind === "deny") emitDeny(decision.reason);
    return;
  }

  const decision = analyzeGhPrCreateCommand(command, policy);
  if (decision.kind === "allow") emitAllow(decision.reason);
  if (decision.kind === "deny") emitDeny(decision.reason);
});
