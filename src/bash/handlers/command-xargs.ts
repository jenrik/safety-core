import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, policyDeny } from "../outcome.js";
import { basename } from "../../shell.js";
import { isSecretPath } from "../../secrets.js";
import { childInvocationFrom, isKnown, known, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

/** Inspect the static command template, but never authorize runtime stdin arguments. */
export const xargsHandler = wrapperHandler("xargs", parseXargs);

const VALUE_OPTIONS = new Set(["-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"]);
const LONG_VALUE_OPTIONS = new Set([
  "--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--process-slot-var",
]);
const FLAGS = new Set(["-0", "-o", "-p", "-r", "-t", "-x", "--null", "--open-tty", "--interactive", "--no-run-if-empty", "--verbose", "--exit", "--show-limits"]);

function parseXargs(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return taintWrapperResult(childInvocationFrom(arguments_, index + 1, context, undefined, "spawn-repeated"), context);
    if (VALUE_OPTIONS.has(argument) || LONG_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      if ((argument === "-a" || argument === "--arg-file") && isSecretPath(arguments_[index + 1]!.value)) {
        return secretArgFileDeny(arguments_[index + 1]!.value, context);
      }
      index += 2;
      continue;
    }
    if (FLAGS.has(argument) || ["-e", "-i", "-l", "--eof", "--replace"].includes(argument)) {
      index++;
      continue;
    }
    if ([...LONG_VALUE_OPTIONS, "--eof", "--replace"].some((option) => argument.startsWith(`${option}=`))) {
      if (argument.startsWith("--arg-file=") && isSecretPath(argument.slice("--arg-file=".length))) {
        return secretArgFileDeny(argument.slice("--arg-file=".length), context);
      }
      index++;
      continue;
    }
    if (argument.startsWith("-a") && argument.length > 2 && isSecretPath(argument.slice(2))) {
      return secretArgFileDeny(argument.slice(2), context);
    }
    const short = parseShortOptions(argument, arguments_[index + 1]);
    if (short) {
      if (short.argFile && isSecretPath(short.argFile)) return secretArgFileDeny(short.argFile, context);
      index += short.consumed;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return taintWrapperResult(childInvocationFrom(arguments_, index, context, undefined, "spawn-repeated"), context);
  }
  return indeterminate(context.span);
}

function secretArgFileDeny(path: string, context: StructuralDispatchContext) {
  return policyDeny(context.span, Object.freeze({
    name: "secret-read",
    decision: "deny" as const,
    reason: `bash \`xargs\` on '${basename(path)}'`,
  }));
}

function parseShortOptions(argument: string, next: ResolvedWord | undefined): { readonly consumed: 1 | 2; readonly argFile?: string } | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (["0", "o", "p", "r", "t", "x"].includes(option)) continue;
    if (["e", "i", "l"].includes(option)) return { consumed: 1 };
    if (!["a", "d", "E", "I", "L", "n", "P", "s"].includes(option)) return undefined;
    const attached = options.slice(index + 1);
    if (attached.length > 0) return { consumed: 1, ...(option === "a" ? { argFile: attached } : {}) };
    if (!isKnown(next)) return undefined;
    return { consumed: 2, ...(option === "a" ? { argFile: next.value } : {}) };
  }
  return { consumed: 1 };
}
