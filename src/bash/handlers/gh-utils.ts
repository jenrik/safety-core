import type { CommandHandler } from "../dispatch.js";

export const GLOBAL_VALUE_FLAGS = new Set(["-R", "--repo", "--hostname"]);
export const PR_VALUE_FLAGS = new Set(["-R", "--repo", "-a", "--assignee", "-B", "--base", "-b", "--body", "-F", "--body-file", "-H", "--head", "-l", "--label", "-m", "--milestone", "-p", "--project", "--recover", "-r", "--reviewer", "-t", "--title", "-T", "--template"]);
export const REPO_FLAGS = new Set(["-R", "--repo"]);
export const KNOWN_TOP_LEVEL = new Set(["alias", "api", "attestation", "agent", "agent-task", "agent-tasks", "agents", "at", "auth", "browse", "cache", "codespace", "completion", "config", "copilot", "discussion", "environment", "exit-codes", "extension", "ext", "extensions", "gist", "gpg-key", "help", "issue", "label", "licenses", "org", "pr", "preview", "project", "release", "repo", "rs", "ruleset", "run", "search", "secret", "skill", "skills", "ssh-key", "status", "variable", "version", "workflow"]);

export function knownArguments(cursor: Parameters<CommandHandler["handle"]>[0]): string[] | undefined {
  return cursor.invocation.argv.every((argument) => argument.kind === "known")
    ? cursor.invocation.argv.map((argument) => argument.value)
    : undefined;
}

export function findSubcommand(args: readonly string[]): { readonly name: string; readonly index: number } | undefined {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (GLOBAL_VALUE_FLAGS.has(argument)) { index++; continue; }
    if (attached(argument, GLOBAL_VALUE_FLAGS) || argument.startsWith("-")) continue;
    return { name: argument, index };
  }
  return undefined;
}

export function isPrCreate(args: readonly string[]): boolean {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "create" || argument === "new") return true;
    if (PR_VALUE_FLAGS.has(argument)) { index++; continue; }
    if (attached(argument, PR_VALUE_FLAGS) || argument.startsWith("-")) continue;
    return false;
  }
  return false;
}

export function repositoryValues(args: readonly string[]): string[] | undefined {
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

export function methodValue(args: readonly string[]): string | null | undefined {
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
export function apiEndpoint(args: readonly string[]): string | undefined {
  const valueFlags = new Set(["-X", "--method", "-f", "--raw-field", "-F", "--field", "--input", "-H", "--header", "--hostname", "--cache"]);
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (valueFlags.has(argument)) { index++; continue; }
    if ([...valueFlags].some((flag) => argument.startsWith(`${flag}=`)) || /^-[XfFH].+/.test(argument)) continue;
    if (!argument.startsWith("-")) return argument;
  }
  return undefined;
}

export function commandScript(args: readonly string[]): string | undefined {
  const index = args.findIndex((argument) => argument === "-c" || argument === "--command");
  return index === -1 ? undefined : args[index + 1];
}

function attached(argument: string, flags: ReadonlySet<string>): boolean {
  const equals = argument.indexOf("=");
  return equals !== -1 && flags.has(argument.slice(0, equals));
}
