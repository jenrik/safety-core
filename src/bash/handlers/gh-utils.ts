import type { InvocationCursor } from "../dispatch.js";

export const GLOBAL_VALUE_FLAGS = new Set(["-R", "--repo", "--hostname"]);
const API_VALUE_FLAGS = new Set([
  "-X", "--method", "-f", "--raw-field", "-F", "--field", "-H", "--header", "--input", "--cache",
  "-p", "--preview", "-q", "--jq", "-t", "--template",
]);
const PR_VALUE_FLAGS = new Set([
  "-t", "--title", "-b", "--body", "-F", "--body-file", "-B", "--base", "-H", "--head", "-r", "--reviewer",
  "-a", "--assignee", "-l", "--label", "-p", "--project", "-m", "--milestone", "--recover", "-T", "--template", "--attach",
]);

export function knownArguments(cursor: InvocationCursor): string[] | undefined {
  return cursor.invocation.argv.every((argument) => argument.kind === "known")
    ? cursor.invocation.argv.map((argument) => argument.value)
    : undefined;
}

export function findSubcommand(args: readonly string[]): { readonly name: string; readonly index: number } | undefined {
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (GLOBAL_VALUE_FLAGS.has(argument) || API_VALUE_FLAGS.has(argument) || PR_VALUE_FLAGS.has(argument)) { index++; continue; }
    if (attached(argument, GLOBAL_VALUE_FLAGS) || attached(argument, API_VALUE_FLAGS) || attached(argument, PR_VALUE_FLAGS)
      || shortAttached(argument, API_VALUE_FLAGS) || shortAttached(argument, PR_VALUE_FLAGS) || argument.startsWith("-")) continue;
    return { name: argument, index };
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

function shortAttached(argument: string, flags: ReadonlySet<string>): boolean {
  return [...flags].some((flag) => flag.length === 2 && argument.startsWith(flag) && argument.length > 2);
}
