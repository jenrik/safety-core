import type { TuiPlugin } from "@opencode-ai/plugin/tui";
import { OPENCODE_POLICY_RELOAD_COMMAND } from "@safety-core/core";

const OPENCODE_V1_PLUGIN_ID = "safety-core.policy-reload";

export const createOpenCodePolicyReloadTuiPlugin: TuiPlugin = async (api) => {
  if (!api.command) throw new Error("OpenCode TUI command registration is unavailable");
  api.command.register(() => [{
    title: "Reload safety policies",
    value: OPENCODE_POLICY_RELOAD_COMMAND,
    description: "Reload the configured safety policies from disk.",
    category: "Safety",
    slash: { name: "safety-reload" },
    onSelect: async () => {
      try {
        await api.client.tui.publish({
          directory: api.state.path.directory,
          body: {
            type: "tui.command.execute",
            properties: { command: OPENCODE_POLICY_RELOAD_COMMAND },
          },
        });
      } catch (error) {
        api.ui.toast({
          title: "Safety policy reload",
          message: error instanceof Error ? error.message : "Could not request a policy reload",
          variant: "error",
        });
      }
    },
  }]);
};

export default {
  id: OPENCODE_V1_PLUGIN_ID,
  tui: createOpenCodePolicyReloadTuiPlugin,
};
