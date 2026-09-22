export interface ParsedGhApiArguments {
  readonly endpoint: string | undefined;
  readonly explicitMethod: string | undefined;
  readonly hasParametersOrBody: boolean;
  readonly methodAmbiguous: boolean;
  readonly unsafeOrMalformed: boolean;
}

const UNSAFE_VALUE_OPTIONS = new Set(["--hostname", "--input", "-H", "--header", "--cache", "-p", "--preview", "-q", "--jq", "-t", "--template"]);
const UNSAFE_BOOLEAN_OPTIONS = new Set(["-i", "--include", "--paginate", "--slurp", "--silent", "--verbose", "--allow-escape-sequences"]);

/** Pure gh api argument parser shared by trusted code policies. */
export function parseGhApiArguments(args: readonly string[], apiIndex: number): ParsedGhApiArguments {
  const endpoints: string[] = [];
  const methods: string[] = [];
  let hasParametersOrBody = false;
  let unsafeOrMalformed = apiIndex !== 0;
  for (let index = 0; index < args.length; index++) {
    if (index === apiIndex) continue;
    const argument = args[index]!;
    if (!argument.startsWith("-") || argument === "-") { endpoints.push(argument); continue; }
    if (argument === "--") { unsafeOrMalformed = true; continue; }
    const short = parseApiShortOptions(args, index, argument);
    if (short) {
      if (short.method !== undefined) methods.push(short.method);
      hasParametersOrBody ||= short.hasParametersOrBody;
      unsafeOrMalformed ||= short.unsafeOrMalformed;
      index = short.lastIndex;
      continue;
    }
    const method = optionValue(args, index, argument, "-X", "--method");
    if (method) { if (!method.value) unsafeOrMalformed = true; else methods.push(method.value); index = method.lastIndex; continue; }
    const rawField = optionValue(args, index, argument, "-f", "--raw-field");
    if (rawField) { hasParametersOrBody = true; if (!validField(rawField.value)) unsafeOrMalformed = true; index = rawField.lastIndex; continue; }
    const typedField = optionValue(args, index, argument, "-F", "--field");
    if (typedField) {
      hasParametersOrBody = true;
      if (!validField(typedField.value) || typedField.value.slice(typedField.value.indexOf("=") + 1).startsWith("@")) unsafeOrMalformed = true;
      index = typedField.lastIndex;
      continue;
    }
    const unsafeValue = [...UNSAFE_VALUE_OPTIONS].find((option) => argument === option || argument.startsWith(`${option}=`) || option.length === 2 && argument.startsWith(option) && argument.length > 2);
    if (unsafeValue) { unsafeOrMalformed = true; if (unsafeValue === "--input") hasParametersOrBody = true; if (argument === unsafeValue) index++; continue; }
    if (UNSAFE_BOOLEAN_OPTIONS.has(argument)) { unsafeOrMalformed = true; continue; }
    unsafeOrMalformed = true;
  }
  return Object.freeze({ endpoint: endpoints.length === 1 ? endpoints[0] : undefined, explicitMethod: methods.at(-1), hasParametersOrBody, methodAmbiguous: false, unsafeOrMalformed: unsafeOrMalformed || endpoints.length !== 1 });
}

function parseApiShortOptions(args: readonly string[], index: number, argument: string): { readonly method?: string; readonly hasParametersOrBody: boolean; readonly unsafeOrMalformed: boolean; readonly lastIndex: number } | undefined {
  if (!argument.startsWith("-") || argument.startsWith("--") || argument === "-") return undefined;
  const options = argument.slice(1);
  let unsafeOrMalformed = false;
  for (let offset = 0; offset < options.length; offset++) {
    const option = options[offset]!;
    if (option === "i") { unsafeOrMalformed = true; continue; }
    if (!["X", "f", "F", "H", "p", "q", "t"].includes(option)) return { hasParametersOrBody: false, unsafeOrMalformed: true, lastIndex: index };
    const attached = options.slice(offset + 1).replace(/^=/, "");
    const separate = attached.length === 0;
    const next = separate ? args[index + 1] : undefined;
    const value = separate && next && !next.startsWith("-") ? next : attached;
    const lastIndex = separate ? index + 1 : index;
    if (!value) return { hasParametersOrBody: option === "f" || option === "F", unsafeOrMalformed: true, lastIndex };
    if (option === "X") return { method: value, hasParametersOrBody: false, unsafeOrMalformed, lastIndex };
    if (option === "f") return { hasParametersOrBody: true, unsafeOrMalformed: unsafeOrMalformed || !validField(value), lastIndex };
    if (option === "F") return { hasParametersOrBody: true, unsafeOrMalformed: unsafeOrMalformed || !validField(value) || value.slice(value.indexOf("=") + 1).startsWith("@"), lastIndex };
    return { hasParametersOrBody: false, unsafeOrMalformed: true, lastIndex };
  }
  return { hasParametersOrBody: false, unsafeOrMalformed, lastIndex: index };
}

function optionValue(args: readonly string[], index: number, argument: string, short: string, long: string): { readonly value: string; readonly lastIndex: number } | undefined {
  if (argument === short || argument === long) { const value = args[index + 1]; return { value: value && !value.startsWith("-") ? value : "", lastIndex: index + 1 }; }
  if (argument.startsWith(`${long}=`)) return { value: argument.slice(long.length + 1), lastIndex: index };
  if (argument.startsWith(`${short}=`)) return { value: argument.slice(short.length + 1), lastIndex: index };
  if (argument.startsWith(short) && argument.length > short.length) return { value: argument.slice(short.length), lastIndex: index };
  return undefined;
}

function validField(value: string): boolean { return value.indexOf("=") > 0; }
