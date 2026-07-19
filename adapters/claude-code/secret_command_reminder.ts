// Claude Code hook: PostToolUse companion for the secret-command LLM judge.
//
// Fires on the same `if` gates as the judge (see secretIfPatterns in the
// claude-code home-manager module) but on PostToolUse — so it only triggers
// after a matching Bash command actually ran, i.e. was allowed. Reminds the
// MAIN AGENT (not the judge) that the "allow" decision is a best-effort
// filter, not a guarantee. Always exits 0; only injects additionalContext.

import { SECRET_COMMAND_REMINDER } from "../../src/index.js";

import { emitPostContext, readStdin, run } from "./_shared.js";

run(() => {
  readStdin(); // drain, unused
  emitPostContext(SECRET_COMMAND_REMINDER);
});
