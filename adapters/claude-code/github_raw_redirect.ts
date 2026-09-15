// Claude Code hook: block direct HTTP requests to raw.githubusercontent.com
// and api.github.com from Bash / WebFetch.

import {
  buildFallbackGithubBlock,
  checkBashForGithub,
  checkWebfetchUrl,
  detectBlockedDomain,
  discoverWasmDir,
  initBashParser,
  isBashParserFailure,
  loadBashAnalysisLimits,
} from "../../src/index.js";

import { emitDeny, parseHookEvent, readStdin, run } from "./_shared.js";

run(async () => {
  // Initialise the bash parser (lazy, first-call only).
  await initBashParser(discoverWasmDir(import.meta.url));

  const raw = readStdin();
  const event = parseHookEvent(raw);

  // If JSON parse failed, fall back to a raw-string domain scan (fail-closed).
  if (!event) {
    const domain = detectBlockedDomain(raw);
    if (domain) emitDeny(buildFallbackGithubBlock(domain));
    return;
  }

  try {
    if (event.tool_name === "Bash") {
      const reason = checkBashForGithub(
        (event.tool_input?.command as string | undefined) ?? "",
        bashAuthorizationContext(),
      );
      if (reason) emitDeny(reason);
      return;
    }
    if (event.tool_name === "WebFetch") {
      const reason = checkWebfetchUrl(
        (event.tool_input?.url as string | undefined) ?? "",
      );
      if (reason) emitDeny(reason);
      return;
    }
  } catch (error) {
    if (isBashParserFailure(error)) throw error;
    const domain = detectBlockedDomain(raw);
    if (domain) emitDeny(buildFallbackGithubBlock(domain));
  }
});

function bashAuthorizationContext() {
  return Object.freeze({
    limits: loadBashAnalysisLimits(),
    initialEnvironment: { kind: "unavailable" as const },
  });
}
