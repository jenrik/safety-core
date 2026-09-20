import type { StructuralDispatchContext } from "../dispatch.js";
import type { ResolvedWord } from "../expand.js";
import { assignBinding, known as knownBinding, setExported, unsetBinding } from "../environment.js";
import { indeterminate } from "../outcome.js";
import { childInvocationFrom, isKnown, known, resolveLongOption, taintWrapperResult, wrapperHandler } from "./wrapper-utils.js";

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
const UNSAFE_FLAGS = new Set(["--output-append-mode", "--output-separately"]);
const LONG_OPTIONS = [
  ...VALUE_OPTIONS,
  ...FLAGS,
  ...OPTIONAL_VALUE_OPTIONS,
  ...UNSAFE_FLAGS,
].filter((option) => option.startsWith("--"));
const UNSAFE_VALUE_OPTIONS = new Set(["-o", "-u", "-E", "--output", "--user", "--env", "--argv0", "--inject", "--fault"]);

export const straceHandler = wrapperHandler("strace", parseStrace);

function parseStrace(arguments_: readonly ResolvedWord[], context: StructuralDispatchContext) {
  let index = 0;
  let unsafe = false;
  let environment = context.environment;
  while (index < arguments_.length) {
    const argument = known(arguments_[index]!, context);
    if (typeof argument !== "string") return argument;
    if (argument === "--") {
      const result = childInvocationFrom(arguments_, index + 1, context, environment, "spawn-and-wait");
      return unsafe ? taintWrapperResult(result, context) : result;
    }
    const long = resolveLongOption(argument, LONG_OPTIONS);
    if (long) {
      if (long.kind === "ambiguous") return indeterminate(context.span);
      const option = long.option;
      if (VALUE_OPTIONS.has(option)) {
        if (long.value === undefined && !isKnown(arguments_[index + 1])) return indeterminate(context.span);
        const value = long.value ?? arguments_[index + 1]!.value;
        if (UNSAFE_VALUE_OPTIONS.has(option) || (option === "--trace" && /^(?:inject|fault)=/.test(value))) unsafe = true;
        if (option === "--env") environment = applyEnvironment(environment, value);
        if (option === "--attach") return indeterminate(context.span);
        index += long.value === undefined ? 2 : 1;
        continue;
      }
      if (FLAGS.has(option) || UNSAFE_FLAGS.has(option)) {
        if (long.value !== undefined) return indeterminate(context.span);
        if (UNSAFE_FLAGS.has(option)) unsafe = true;
        index++;
        continue;
      }
      index++;
      continue;
    }
    if (VALUE_OPTIONS.has(argument)) {
      if (!isKnown(arguments_[index + 1])) return indeterminate(context.span);
      if (UNSAFE_VALUE_OPTIONS.has(argument) || (argument === "-e" && /^(?:inject|fault)=/.test(arguments_[index + 1]!.value))) unsafe = true;
      if (argument === "-E" || argument === "--env") environment = applyEnvironment(environment, arguments_[index + 1]!.value);
      if (argument === "-p" || argument === "--attach") return indeterminate(context.span);
      index += 2;
      continue;
    }
    if (FLAGS.has(argument)) {
      index++;
      continue;
    }
    if (argument === "-ff" || argument === "-A" || UNSAFE_FLAGS.has(argument)) {
      unsafe = true;
      index++;
      continue;
    }
    const longValue = [...VALUE_OPTIONS].find((option) => option.startsWith("--") && argument.startsWith(`${option}=`));
    if (longValue) {
      if (longValue === "--attach") return indeterminate(context.span);
      if (UNSAFE_VALUE_OPTIONS.has(longValue) || ((longValue === "--trace") && /^(?:inject|fault)=/.test(argument.slice(longValue.length + 1)))) unsafe = true;
      if (longValue === "--env") environment = applyEnvironment(environment, argument.slice(longValue.length + 1));
      index++;
      continue;
    }
    if (OPTIONAL_VALUE_OPTIONS.some((option) => argument === option || argument.startsWith(`${option}=`))) {
      index++;
      continue;
    }
    if (argument.startsWith("-E") && argument.length > 2) {
      environment = applyEnvironment(environment, argument.slice(2));
      unsafe = true;
      index++;
      continue;
    }
    const short = parseShortOptions(argument, arguments_[index + 1]);
    if (short) {
      if (short.attach) return indeterminate(context.span);
      if (short.unsafe) unsafe = true;
      if (short.environment !== undefined) environment = applyEnvironment(environment, short.environment);
      index += short.consumed;
      continue;
    }
    if (argument.startsWith("-")) return indeterminate(context.span);
    const result = childInvocationFrom(arguments_, index, context, environment, "spawn-and-wait");
    return unsafe ? taintWrapperResult(result, context) : result;
  }
  return indeterminate(context.span);
}

function applyEnvironment(environment: StructuralDispatchContext["environment"], value: string) {
  const match = /^([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$/s.exec(value);
  if (!match) return environment;
  const name = match[1]!;
  return match[2] === undefined
    ? unsetBinding(environment, name)
    : setExported(assignBinding(environment, name, knownBinding(match[2])), name, true);
}

function parseShortOptions(argument: string, next: ResolvedWord | undefined): {
  readonly consumed: 1 | 2;
  readonly unsafe: boolean;
  readonly attach: boolean;
  readonly environment?: string;
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
    return Object.freeze({
      consumed: attachedValue ? 1 : 2,
      unsafe,
      attach: option === "p",
      ...(option === "E" ? { environment: value } : {}),
    });
  }
  return Object.freeze({ consumed: 1, unsafe, attach: false });
}
