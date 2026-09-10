// Claude Code hook for the parsed gh/Helm read-only profiles.

import {
  analyzeGhReadOnlyCommand,
  analyzeHelmReadOnlyCommand,
  discoverWasmDir,
  initBashParser,
  isProfileEnabled,
} from "../../src/index.js";
import { emitAllow, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  if (!isProfileEnabled("ghReadOnly") && !isProfileEnabled("helmReadOnly")) return;
  await initBashParser(discoverWasmDir(import.meta.url));

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;
  const command = (event.tool_input?.command as string | undefined) ?? "";
  if (isProfileEnabled("ghReadOnly")) {
    const decision = analyzeGhReadOnlyCommand(command);
    if (decision.kind === "allow") {
      emitAllow(decision.reason);
      return;
    }
    if (decision.kind !== "ignore") return;
  }

  if (isProfileEnabled("helmReadOnly")) {
    const decision = analyzeHelmReadOnlyCommand(command);
    if (decision.kind === "allow") emitAllow(decision.reason);
  }
});
