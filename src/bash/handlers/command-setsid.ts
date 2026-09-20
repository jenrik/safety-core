import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { childInvocationFrom, known, resolveLongOption, wrapperHandler } from "./wrapper-utils.js";

const LONG_OPTIONS = ["--ctty", "--fork", "--wait", "--help", "--version"];

export const setsidHandler = wrapperHandler("setsid", parseSetsid);

function parseSetsid(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  let forks = false;
  let waits = false;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") return childInvocationFrom(arguments_, index + 1, context, undefined, setsidEffect(forks, waits));
    const long = resolveLongOption(argument, LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous" || long.value !== undefined) break;
      forks ||= long.option === "--fork";
      waits ||= long.option === "--wait";
      index++;
      continue;
    }
    if (/^-[cfw]+$/.test(argument) || ["--ctty", "--fork", "--wait"].includes(argument)) {
      forks ||= argument.includes("f") || argument === "--fork";
      waits ||= argument.includes("w") || argument === "--wait";
      index++;
      continue;
    }
    break;
  }
  return childInvocationFrom(arguments_, index, context, undefined, setsidEffect(forks, waits));
}

function setsidEffect(forks: boolean, waits: boolean) {
  if (forks) return waits ? "spawn-and-wait" as const : "spawn-async" as const;
  return waits ? "unknown" as const : "exec-replace" as const;
}
