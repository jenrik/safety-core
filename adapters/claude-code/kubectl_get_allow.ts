// Claude Code hook: auto-allow read-only and safe kubectl subcommands.
//
// Flags like -n, --context can appear anywhere on the command line, so the
// harness' prefix-based permission model can't cover every variation on its
// own. This hook parses the command and emits an allow / deny decision;
// silent exit means "defer to default permissions".

import { analyzeKubectl } from "../../src/index.js";

import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(() => {
  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  const decision = analyzeKubectl(command);

  switch (decision.kind) {
    case "allow":
      emitAllow(decision.reason);
      return;
    case "deny":
      emitDeny(decision.reason);
      return;
    // defer / ignore → exit 0 silently
  }
});
