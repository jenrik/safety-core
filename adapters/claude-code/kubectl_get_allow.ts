// Claude Code hook for the opt-in, credential-safe kubectl profile.
//
// Flags like -n, --context can appear anywhere on the command line, so the
// harness' prefix-based permission model can't cover every variation on its
// own. This hook parses the command and emits an allow / deny decision;
// silent exit means "defer to default permissions".

import {
  analyzeStrictReadOnlyCommand,
  discoverWasmDir,
  initBashParser,
  isProfileEnabled,
} from "../../src/index.js";

import { emitAllow, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  if (!isProfileEnabled("kubectlReadOnly")) return;
  // Initialise the bash parser (lazy, first-call only).
  await initBashParser(discoverWasmDir(import.meta.url));

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  const decision = analyzeStrictReadOnlyCommand(command, "kubectl");

  switch (decision.kind) {
    case "allow":
      emitAllow(decision.reason);
      return;
    // defer / ignore → exit 0 silently
  }
});
