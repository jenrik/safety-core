import type { InvocationCursor } from "../dispatch.js";

export const GLOBAL_VALUE_FLAGS = new Set(["-R", "--repo", "--hostname"]);

export function knownArguments(cursor: InvocationCursor): string[] | undefined {
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

export function commandScript(args: readonly string[]): string | undefined {
  const index = args.findIndex((argument) => argument === "-c" || argument === "--command");
  return index === -1 ? undefined : args[index + 1];
}

function attached(argument: string, flags: ReadonlySet<string>): boolean {
  const equals = argument.indexOf("=");
  return equals !== -1 && flags.has(argument.slice(0, equals));
}
