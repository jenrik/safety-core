// Claude Code hook: secrets policy.
//
// - SessionStart / SubagentStart: emit the policy file to stdout for context.
// - PreToolUse Read: hard-block reads of files that contain secret VALUES
//   (exit 2 + stderr message).

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import {
  SECRETS_POLICY_FALLBACK,
  basename,
  buildSecretBlockMessage,
  isSecretPath,
} from "@safety-core/core";

import { hardBlock, parseHookEvent, readStdin, run } from "./_shared.js";

const POLICY_FILE = join(homedir(), ".claude", "rules", "secrets-policy.md");

function loadPolicy(): string {
  try {
    return readFileSync(POLICY_FILE, "utf-8");
  } catch {
    return `${SECRETS_POLICY_FALLBACK}(Expected canonical file at ${POLICY_FILE}.)\n`;
  }
}

function handleSessionStart(): void {
  process.stdout.write(loadPolicy());
}

function handlePreToolUseRead(event: ReturnType<typeof parseHookEvent>): void {
  const path = (event?.tool_input?.file_path as string | undefined) ?? "";
  if (path && isSecretPath(path)) {
    hardBlock(buildSecretBlockMessage(`Read on '${basename(path)}'`));
  }
}

run(() => {
  const event = parseHookEvent(readStdin());
  if (!event) return;

  switch (event.hook_event_name) {
    case "SessionStart":
    case "SubagentStart":
      handleSessionStart();
      return;
    case "PreToolUse":
      if (event.tool_name === "Read") handlePreToolUseRead(event);
       return;
  }
});
