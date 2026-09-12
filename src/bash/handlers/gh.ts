import type { GhPrCreatePolicy } from "../../gh-pr-create.js";
import { parseBashProgram } from "../../shell.js";
import type { BashStatement } from "../cst.js";
import type { CommandHandler } from "../dispatch.js";
import { indeterminate, policyDeny, policyIndeterminate, policySafe, safe } from "../outcome.js";
import { analyzeGhApiInvocation } from "../policies/gh-api.js";
import { analyzeGhPrCreateInvocation, denyGhPrCreate } from "../policies/gh-pr-create.js";

const GLOBAL_VALUE_FLAGS = new Set(["-R", "--repo", "--hostname"]);
const PR_VALUE_FLAGS = new Set(["-R", "--repo", "-a", "--assignee", "-B", "--base", "-b", "--body", "-F", "--body-file", "-H", "--head", "-l", "--label", "-m", "--milestone", "-p", "--project", "--recover", "-r", "--reviewer", "-t", "--title", "-T", "--template"]);
const REPO_FLAGS = new Set(["-R", "--repo"]);
const KNOWN_TOP_LEVEL = new Set(["alias", "api", "attestation", "agent", "agent-task", "agent-tasks", "agents", "at", "auth", "browse", "cache", "codespace", "completion", "config", "copilot", "discussion", "environment", "exit-codes", "extension", "ext", "extensions", "gist", "gpg-key", "help", "issue", "label", "licenses", "org", "pr", "preview", "project", "release", "repo", "rs", "ruleset", "run", "search", "secret", "skill", "skills", "ssh-key", "status", "variable", "version", "workflow"]);

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

export function ghPrCreateHandler(policy: GhPrCreatePolicy): CommandHandler {
  return Object.freeze({
    name: "gh",
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) {
        const first = cursor.invocation.argv[0];
        return first?.kind === "known" && ["alias", "extension", "ext", "extensions"].includes(first.value)
          ? denied(context, first.value === "alias"
            ? "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead"
            : "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead")
          : indeterminate(context.span);
      }
      const subcommand = findSubcommand(args);
      if (!subcommand) return indeterminate(context.span);
      if (!KNOWN_TOP_LEVEL.has(subcommand.name)) return denied(context, "Unknown gh command blocked: it could be an alias or extension that bypasses the ghPrCreate policy; use native gh pr create instead");
      if (subcommand.name === "api") return denied(context, "GitHub API calls are blocked while ghPrCreate is enabled: use the matching native gh subcommand instead");
      if (subcommand.name === "alias" && ["set", "import"].includes(args[subcommand.index + 1] ?? "")) {
        return denied(context, "GitHub CLI alias definitions are blocked while ghPrCreate is enabled; invoke native gh pr create with an explicit allowlisted --repo target instead");
      }
      if (["extension", "ext", "extensions"].includes(subcommand.name) && args[subcommand.index + 1] === "exec") {
        return denied(context, "GitHub CLI extensions cannot create pull requests under the ghPrCreate policy; use native gh pr create instead");
      }
      if (subcommand.name !== "pr" || !isPrCreate(args.slice(subcommand.index + 1))) return indeterminate(context.span);
      const decision = analyzeGhPrCreateInvocation(repositoryValues(args), policy);
      return decision.kind === "allow" ? policySafe(decision.evidence) : policyDeny(context.span, decision.evidence);
    },
  });
}

/** Re-dispatch literal interpreter payloads; the child invocation owns its policy decision. */
export const ghPrCreateShellHandlers: readonly CommandHandler[] = Object.freeze(
  ["eval", "sh", "bash", "dash", "fish", "ksh", "zsh"].map((name) => Object.freeze({
    name,
    handle(cursor, context) {
      const args = knownArguments(cursor);
      if (!args) return indeterminate(context.span);
      const script = name === "eval" ? args.join(" ") : commandScript(args);
      if (!script && context.inPipeline) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      if (script && scriptContainsGhAttempt(script)) {
        return denied(context, "Pull-request creation is blocked through a shell interpreter; invoke native gh pr create as a standalone command instead");
      }
      return script ? context.continueWith(script) : indeterminate(context.span);
    },
  })),
);

function denied(context: Parameters<CommandHandler["handle"]>[1], reason: string) {
  return policyDeny(context.span, denyGhPrCreate(reason).evidence);
}

function knownArguments(cursor: Parameters<CommandHandler["handle"]>[0]): string[] | undefined {
  return cursor.invocation.argv.every((argument) => argument.kind === "known")
    ? cursor.invocation.argv.map((argument) => argument.value)
    : undefined;
}

function findSubcommand(args: readonly string[]): { readonly name: string; readonly index: number } | undefined {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (GLOBAL_VALUE_FLAGS.has(argument)) { index++; continue; }
    if (attached(argument, GLOBAL_VALUE_FLAGS) || argument.startsWith("-")) continue;
    return { name: argument, index };
  }
  return undefined;
}

function isPrCreate(args: readonly string[]): boolean {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "create" || argument === "new") return true;
    if (PR_VALUE_FLAGS.has(argument)) { index++; continue; }
    if (attached(argument, PR_VALUE_FLAGS) || argument.startsWith("-")) continue;
    return false;
  }
  return false;
}

function repositoryValues(args: readonly string[]): string[] | undefined {
  const repositories: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (REPO_FLAGS.has(argument)) {
      const value = args[++index];
      if (!value || value.startsWith("-")) return undefined;
      repositories.push(value);
    } else if (argument.startsWith("--repo=") || argument.startsWith("-R=")) {
      const value = argument.slice(argument.indexOf("=") + 1);
      if (!value) return undefined;
      repositories.push(value);
    } else if (argument.startsWith("-R") && argument.length > 2) repositories.push(argument.slice(2));
    else if (PR_VALUE_FLAGS.has(argument) || GLOBAL_VALUE_FLAGS.has(argument)) index++;
    else if (attached(argument, PR_VALUE_FLAGS) || attached(argument, GLOBAL_VALUE_FLAGS)) continue;
  }
  return repositories;
}

function methodValue(args: readonly string[]): string | null | undefined {
  const values: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "-X" || argument === "--method") {
      const value = args[++index];
      if (!value || value.startsWith("-")) return null;
      values.push(value);
      continue;
    }
    const equals = argument.indexOf("=");
    if (equals !== -1 && (argument.slice(0, equals) === "-X" || argument.slice(0, equals) === "--method")) {
      const value = argument.slice(equals + 1);
      if (!value) return null;
      values.push(value);
      continue;
    }
    if (argument.startsWith("-X") && argument.length > 2) values.push(argument.slice(2));
  }
  return values.length === 0 ? undefined : values.length === 1 ? values[0]! : null;
}

/** Consume only documented API option values before selecting the endpoint. */
function apiEndpoint(args: readonly string[]): string | undefined {
  const valueFlags = new Set(["-X", "--method", "-f", "--raw-field", "-F", "--field", "--input", "-H", "--header", "--hostname", "--cache"]);
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (valueFlags.has(argument)) { index++; continue; }
    if ([...valueFlags].some((flag) => argument.startsWith(`${flag}=`)) || /^-[XfFH].+/.test(argument)) continue;
    if (!argument.startsWith("-")) return argument;
  }
  return undefined;
}

function attached(argument: string, flags: ReadonlySet<string>): boolean {
  const equals = argument.indexOf("=");
  return equals !== -1 && flags.has(argument.slice(0, equals));
}

function commandScript(args: readonly string[]): string | undefined {
  const index = args.findIndex((argument) => argument === "-c" || argument === "--command");
  return index === -1 ? undefined : args[index + 1];
}

function scriptContainsGhAttempt(source: string): boolean {
  const program = parseBashProgram(source);
  return program.kind === "program" && program.statements.some(statementContainsGhAttempt);
}

function statementContainsGhAttempt(statement: BashStatement): boolean {
  if (statement.kind === "command") {
    const words = statement.words.map((word) => word.text);
    return words[0] === "gh" && ((words[1] === "pr" && ["create", "new"].includes(words[2] ?? "")) || words[1] === "api");
  }
  if (statement.kind === "function") return statementContainsGhAttempt(statement.body);
  if (statement.kind === "if") {
    return [...statement.condition, ...statement.consequent, ...statement.alternate].some(statementContainsGhAttempt);
  }
  return statement.statements.some(statementContainsGhAttempt);
}
