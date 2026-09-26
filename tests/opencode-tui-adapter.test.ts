import { expect, test } from "bun:test";

import { createOpenCodePolicyReloadTuiPlugin } from "../adapters/opencode-tui.ts";
import { OPENCODE_POLICY_RELOAD_COMMAND } from "../src/index.ts";

test("OpenCode registers policy reload as a human TUI command, not an agent tool", async () => {
  let commands: Array<{ value: string; onSelect: () => Promise<void> }> = [];
  const published: unknown[] = [];
  await createOpenCodePolicyReloadTuiPlugin({
    command: {
      register: (register: () => typeof commands) => {
        commands = register();
        return () => {};
      },
    },
    client: { tui: { publish: async (value: unknown) => { published.push(value); } } },
    state: { path: { directory: "/workspace" } },
    ui: { toast() {} },
  } as never, undefined, {} as never);

  expect(commands).toHaveLength(1);
  expect(commands[0]!.value).toBe(OPENCODE_POLICY_RELOAD_COMMAND);
  await commands[0]!.onSelect();
  expect(published).toEqual([{
    directory: "/workspace",
    body: {
      type: "tui.command.execute",
      properties: { command: OPENCODE_POLICY_RELOAD_COMMAND },
    },
  }]);
});

test("OpenCode TUI reload does not expose a tool registration path", async () => {
  const exports = await import("../adapters/opencode-tui.ts");
  expect(Object.keys(exports)).not.toContain("tool");
  expect(Object.keys(exports)).not.toContain("createTool");
});
