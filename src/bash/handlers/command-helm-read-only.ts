import type { CommandHandler } from "../dispatch.js";
import { HELM_CREDENTIAL_SAFE_COMMANDS } from "../policies/read-only.js";
import { allow, defer, hasSecretOperand, readOnlyHandler } from "./read-only-utils.js";

export const helmReadOnlyHandler: CommandHandler = readOnlyHandler("helm", "helm-read-only", (args) => {
  if (hasSecretOperand(args)) return defer("helm-read-only", "helm");
  if (args.length === 1 && ["--help", "--version"].includes(args[0]!)) return allow("helm-read-only", "helm");
  if (args.some((argument) => argument.startsWith("-"))) return defer("helm-read-only", "helm");
  const [root, second] = args;
  if (!root) return defer("helm-read-only", "helm");
  if (root === "help") return allow("helm-read-only", "helm");
  if (root === "completion") return args.length === 2 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  if (root === "verify") return args.length >= 2 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  const path = second ? `${root}:${second}` : root;
  if (["show:chart", "inspect:chart"].includes(path)) return args.length === 3 ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
  return HELM_CREDENTIAL_SAFE_COMMANDS.has(path) ? allow("helm-read-only", "helm") : defer("helm-read-only", "helm");
});
