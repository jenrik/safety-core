import type { LoadedPolicyRuntime } from "./runtime.js";

/** Name of the OpenCode TUI action that the server adapter accepts. */
export const OPENCODE_POLICY_RELOAD_COMMAND = "safety-core.policy.reload";

export interface PolicyRuntimeReloader {
  ensure(cwd: string): Promise<LoadedPolicyRuntime>;
  reload(cwd: string): Promise<LoadedPolicyRuntime>;
  current(): LoadedPolicyRuntime | undefined;
}

/**
 * Keep the last successful runtime active while a human-requested reload is
 * in flight. A stale reload result cannot replace a newer successful reload.
 */
export function createPolicyRuntimeReloader(
  loadRuntime: (cwd: string) => Promise<LoadedPolicyRuntime>,
  initial?: Promise<LoadedPolicyRuntime>,
): PolicyRuntimeReloader {
  let active: LoadedPolicyRuntime | undefined;
  let startup = initial;
  let revision = 0;

  return {
    async ensure(cwd) {
      if (active) return active;
      startup ??= loadRuntime(cwd);
      const expectedRevision = revision;
      const loaded = await startup;
      if (expectedRevision === revision) active = loaded;
      return active ?? loaded;
    },
    async reload(cwd) {
      const expectedRevision = ++revision;
      const loaded = await loadRuntime(cwd);
      if (expectedRevision === revision) active = loaded;
      return loaded;
    },
    current() {
      return active;
    },
  };
}
