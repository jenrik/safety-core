import type { CommandHandler } from "../dispatch.js";
import { indeterminate, policyDeny, policyIndeterminate, policySafe } from "../outcome.js";
import { analyzeGhApiInvocation } from "../policies/gh-api.js";
import { apiEndpoint, findSubcommand, knownArguments, methodValue } from "./gh-utils.js";

export const ghApiHandler: CommandHandler = Object.freeze({
  name: "gh",
  handle(cursor, context) {
    const args = knownArguments(cursor);
    if (!args) return indeterminate(context.span);
    const subcommand = findSubcommand(args);
    if (!subcommand || subcommand.name !== "api") return indeterminate(context.span);
    const api = args.slice(subcommand.index + 1);
    const endpoint = apiEndpoint(api);
    const explicitMethod = methodValue(api);
    const hasParametersOrBody = api.some((argument) => ["-f", "--raw-field", "-F", "--field", "--input"].includes(argument)
      || ["--raw-field", "--field", "--input"].some((flag) => argument.startsWith(`${flag}=`))
      || /^-[fF].+/.test(argument));
    const decision = analyzeGhApiInvocation({ endpoint, explicitMethod: explicitMethod ?? undefined, hasParametersOrBody, methodAmbiguous: explicitMethod === null });
    return decision.kind === "allow" ? policySafe(decision.evidence)
      : decision.kind === "deny" ? policyDeny(context.span, decision.evidence)
      : policyIndeterminate(context.span, decision.evidence);
  },
});
