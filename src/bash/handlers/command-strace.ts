import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { indeterminate } from "../outcome.js";
import { continueFrom, isKnown, known, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

const VALUE_OPTIONS = new Set([
  "-e", "-o", "-p", "-P", "-s", "-u", "-E", "-a", "-I", "-b", "-X", "-O", "-S", "-U", "-Y",
  "--env", "--output", "--attach", "--trace-path", "--string-limit", "--user", "--columns", "--interruptible",
  "--detach-on", "--const-print-style", "--summary-syscall-overhead", "--summary-sort-by", "--summary-columns",
  "--argv0", "--stack-trace-frame-limit", "--syscall-limit", "--decode-pids",
  "--trace", "--signal", "--status", "--trace-fds", "--abbrev", "--verbose", "--raw", "--read", "--write",
  "--kvm", "--namespace", "--inject", "--fault",
]);
const FLAGS = new Set([
  "-f", "-c", "-C", "-D", "-DD", "-DDD", "-d", "-h", "-i", "-k", "-kk", "-n", "-N", "-q", "-qq", "-qqq",
  "-r", "-t", "-tt", "-ttt", "-T", "-v", "-V", "-w", "-x", "-xx", "-y", "-yy", "-z", "-Z",
  "--follow-forks", "--seccomp-bpf", "--kill-on-exit", "--successful-only", "--failed-only", "--instruction-pointer",
  "--syscall-number", "--arg-names", "--no-abbrev", "--always-show-pid", "--summary-only", "--summary", "--summary-wall-clock",
  "--debug", "--help", "--version",
]);
const OPTIONAL_VALUE_OPTIONS = [
  "--daemonize", "--color", "--stack-trace", "--quiet", "--relative-timestamps", "--absolute-timestamps",
  "--syscall-times", "--strings-in-hex", "--decode-fds", "--tips",
] as const;
const UNSAFE_VALUE_OPTIONS = new Set(["-o", "-u", "-E", "--output", "--user", "--env", "--argv0", "--inject", "--fault"]);

export const straceHandler = wrapperHandler("strace", parseStrace);

function parseStrace(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  let unsafe = false;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") {
      const result = continueFrom(arguments_, index + 1, context);
      return unsafe ? taintWrapperResult(result, context) : result;
    }
    if (VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      if (UNSAFE_VALUE_OPTIONS.has(argument) || (argument === "-e" && /^(?:inject|fault)=/.test(arguments_[index + 1]!.value))) unsafe = true;
      if (argument === "-p" || argument === "--attach") return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (FLAGS.has(argument)) {
      index++;
      continue;
    }
    if (argument === "-ff" || argument === "-A" || argument === "--output-append-mode" || argument === "--output-separately") {
      unsafe = true;
      index++;
      continue;
    }
    const longValue = [...VALUE_OPTIONS].find((option) => option.startsWith("--") && argument.startsWith(`${option}=`));
    if (longValue) {
      if (longValue === "--attach") return indeterminate(context.span);
      if (UNSAFE_VALUE_OPTIONS.has(longValue) || ((longValue === "--trace") && /^(?:inject|fault)=/.test(argument.slice(longValue.length + 1)))) unsafe = true;
      index++;
      continue;
    }
    if (OPTIONAL_VALUE_OPTIONS.some((option) => argument === option || argument.startsWith(`${option}=`))) {
      index++;
      continue;
    }
    const short = parseShortOptions(argument, arguments_[index + 1]);
    if (short) {
      if (short.attach) return indeterminate(context.span);
      if (short.unsafe) unsafe = true;
      index += short.consumed;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    const result = continueFrom(arguments_, index, context);
    return unsafe ? taintWrapperResult(result, context) : result;
  }
  return indeterminate(context.span);
}

function parseShortOptions(argument: string, next: ResolvedWord | undefined): {
  readonly consumed: 1 | 2;
  readonly unsafe: boolean;
  readonly attach: boolean;
} | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument.length < 2) return undefined;
  const options = argument.slice(1);
  const flags = new Set("ACDcdfhijkNnqrTtvVwxyzZ".split(""));
  const values = new Set("aIbeopPsSuUEXO Y".replaceAll(" ", "").split(""));
  let unsafe = options.includes("A") || options.includes("ff");
  for (let index = 0; index < options.length; index++) {
    const option = options[index]!;
    if (flags.has(option)) continue;
    if (!values.has(option)) return undefined;
    const attachedValue = options.slice(index + 1);
    if (!attachedValue && !isKnown(next)) return undefined;
    const value = attachedValue || next!.value;
    if (["o", "u", "E"].includes(option) || (option === "e" && /^(?:inject|fault)=/.test(value))) unsafe = true;
    return Object.freeze({ consumed: attachedValue ? 1 : 2, unsafe, attach: option === "p" });
  }
  return Object.freeze({ consumed: 1, unsafe, attach: false });
}
