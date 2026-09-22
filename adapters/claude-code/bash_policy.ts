// Claude Code hook: one configured, single-pass policy evaluation for Bash.

import { discoverWasmDir, initBashParser, loadPolicyRuntime } from "../../src/index.js";
import { evaluateClaudeBashPolicy, isBashPreToolUse } from "./_bash_policy.js";
import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  const event = parseHookEvent(readStdin());
  if (!isBashPreToolUse(event)) return;

  await initBashParser(discoverWasmDir(import.meta.url));
  const decision = evaluateClaudeBashPolicy(event, { runtime: await loadPolicyRuntime(event.cwd ?? process.cwd()) });
  if (decision?.kind === "allow") emitAllow(decision.reason);
  if (decision?.kind === "deny") emitDeny(decision.reason);
});
