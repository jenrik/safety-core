// Claude Code hook: block direct HTTP requests to raw.githubusercontent.com
// and api.github.com from WebFetch.

import {
  buildFallbackGithubBlock,
  checkWebfetchUrl,
  detectBlockedDomain,
} from "@safety-core/core";

import { emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(() => {
  const raw = readStdin();
  const event = parseHookEvent(raw);

  // If JSON parse failed, fall back to a raw-string domain scan (fail-closed).
  if (!event) {
    const domain = detectBlockedDomain(raw);
    if (domain) emitDeny(buildFallbackGithubBlock(domain));
    return;
  }

  if (event.hook_event_name === "PreToolUse" && event.tool_name === "WebFetch") {
    const reason = checkWebfetchUrl(
      (event.tool_input?.url as string | undefined) ?? "",
    );
    if (reason) emitDeny(reason);
  }
});
