import type { CommandHandler } from "../dispatch.js";
import { kubectlResourceOperandsRequireReview } from "../policies/kubectl.js";
import { STRICT_ALLOWED_FLAGS, STRICT_READ_ONLY_COMMANDS } from "../policies/read-only.js";
import { allow, defer, hasSecretOperand, parseAllowedFlags, readOnlyHandler } from "./read-only-utils.js";

export function strictReadOnlyHandler(executable: string): CommandHandler {
  return readOnlyHandler(executable, "strict-read-only", (args) => {
    if (hasSecretOperand(args)) return defer("strict-read-only", executable);
    if (args.length === 1 && ["--help", "--version", "version"].includes(args[0]!)) return allow("strict-read-only", executable);
    const positionals = parseAllowedFlags(args, STRICT_ALLOWED_FLAGS[executable] ?? []);
    if (!positionals) return defer("strict-read-only", executable);
    const allowed = STRICT_READ_ONLY_COMMANDS[executable]!;
    const path = strictPath(positionals, allowed);
    if (!path || (path === "version" && positionals.length !== 1)) return defer("strict-read-only", executable);
    if (["kubectl", "oc"].includes(executable) && path === "get") {
      const resources = positionals.slice(1);
      if (resources.length === 0 || kubectlResourceOperandsRequireReview(resources)) return defer("strict-read-only", executable);
    }
    return allow("strict-read-only", executable);
  });
}

function strictPath(args: readonly string[], allowed: ReadonlySet<string>): string | undefined {
  return [...allowed].sort((left, right) => right.split(":").length - left.split(":").length)
    .find((path) => path.split(":").every((token, index) => args[index] === token));
}
