import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate, policyDeny } from "../outcome.js";
import { basename } from "../../shell.js";
import { isSecretPath } from "../../secrets.js";
import { continueFrom, isKnown, known, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

const VALUE_OPTIONS = new Set(["-C", "-D", "-g", "-h", "-p", "-R", "-T", "-U", "-u"]);
const LONG_VALUE_OPTIONS = new Set([
  "--close-from", "--chdir", "--group", "--host", "--prompt", "--chroot", "--command-timeout", "--other-user", "--user",
]);
const FLAGS = new Set(["-A", "-B", "-b", "-E", "-H", "-k", "-N", "-n", "-P", "-S", "-i", "-s", "--askpass", "--background", "--bell", "--preserve-env", "--reset-timestamp", "--set-home", "--non-interactive", "--preserve-groups", "--stdin", "--login", "--shell"]);
const NO_EXEC_OPTIONS = new Set(["-K", "-l", "-V", "-v", "--remove-timestamp", "--list", "--version", "--validate", "--help"]);

export const sudoHandler = wrapperHandler("sudo", parseSudo);
export const sudoeditHandler = wrapperHandler("sudoedit", parseSudoEdit);

function parseSudo(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return taintWrapperResult(continueFrom(arguments_, index + 1, context), context);
    if (argument === "-e" || argument === "--edit") return parseSudoEdit(arguments_.slice(index + 1), context);
    if (NO_EXEC_OPTIONS.has(argument)) return indeterminate(context.span);
    if (VALUE_OPTIONS.has(argument) || LONG_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (FLAGS.has(argument)) { index++; continue; }
    if ([...LONG_VALUE_OPTIONS].some((option) => argument.startsWith(`${option}=`))) { index++; continue; }
    if (argument.startsWith("--preserve-env=")) { index++; continue; }
    const short = parseShortOptions(argument, arguments_[index + 1]);
    if (short?.noExec) return argument.includes("e") ? parseSudoEdit(arguments_.slice(index + short.consumed), context) : indeterminate(context.span);
    if (short) { index += short.consumed; continue; }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(argument)) { index++; continue; }
    if (argument.startsWith("-")) return indeterminate(context.span);
    return taintWrapperResult(continueFrom(arguments_, index, context), context);
  }
  return indeterminate(context.span);
}

function parseSudoEdit(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") { index++; break; }
    if (VALUE_OPTIONS.has(argument) || LONG_VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (FLAGS.has(argument) || NO_EXEC_OPTIONS.has(argument) || argument === "-e" || argument === "--edit") { index++; continue; }
    if ([...LONG_VALUE_OPTIONS].some((option) => argument.startsWith(`${option}=`)) || argument.startsWith("--preserve-env=")) { index++; continue; }
    if (argument.startsWith("-")) { index++; continue; }
    break;
  }
  for (const operand of arguments_.slice(index)) {
    if (operand.kind !== "known") return indeterminate(context.span);
    if (isSecretPath(operand.value)) return secretEditDeny(operand.value, context);
  }
  return indeterminate(context.span);
}

function secretEditDeny(path: string, context: StructuralDispatchContext) {
  return policyDeny(context.span, Object.freeze({
    name: "secret-read",
    decision: "deny" as const,
    reason: `bash \`sudoedit\` on '${basename(path)}'`,
  }));
}

function parseShortOptions(argument: string, next: ResolvedWord | undefined): { readonly consumed: 1 | 2; readonly noExec: boolean } | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (["e", "K", "l", "V", "v"].includes(option)) return { consumed: 1, noExec: true };
    if (["A", "B", "b", "E", "H", "k", "N", "n", "P", "S", "i", "s"].includes(option)) continue;
    if (!["C", "D", "g", "h", "p", "R", "T", "U", "u"].includes(option)) return undefined;
    return {
      consumed: options.slice(index + 1).length > 0 ? 1 : isKnown(next) ? 2 : 1,
      noExec: false,
    };
  }
  return { consumed: 1, noExec: false };
}
