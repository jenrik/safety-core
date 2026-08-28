// Claude Code hook: auto-allow verifiably read-only `gh api` calls.
//
// `gh api`'s read-only-ness depends on the HTTP method (implied by flags,
// not just the command prefix), so the harness' prefix-based permission
// model can't cover it on its own. This hook parses the command and emits
// an allow / deny decision; silent exit means "defer to default
// permissions". Gated by the shared profiles.json config (see
// src/config.ts) rather than by the hook's mere presence, since this hook
// entry is wired in unconditionally by the safety-core home-manager module.

import { analyzeGhApiCommand, discoverWasmDir, initBashParser, isProfileEnabled } from "../../src/index.js";

import { emitAllow, emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  if (!isProfileEnabled("ghApiReadOnly")) return;

  // Initialise the bash parser (lazy, first-call only).
  await initBashParser(discoverWasmDir(import.meta.url));

  const event = parseHookEvent(readStdin());
  if (!event || event.tool_name !== "Bash") return;

  const command = (event.tool_input?.command as string | undefined) ?? "";
  const decision = analyzeGhApiCommand(command);

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
