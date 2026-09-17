import {
  GH_HELP_TOPIC_RULE_BY_NAME,
  GH_READ_ONLY_RULES,
  type GhCommandRule,
  type GhFlagGrammar,
} from "../policies/gh-read-only.js";

export interface ParsedGhOption {
  readonly identity: string;
  readonly spelling: string;
  readonly value?: string;
  readonly position: number;
  readonly scope: "root" | "command";
}

export type ParsedGhCommandLine =
  | { readonly kind: "root-version" }
  | { readonly kind: "root-help" }
  | { readonly kind: "help-topic"; readonly topic: string; readonly disposition: "allow" | "defer" }
  | {
    readonly kind: "command";
    readonly rule: GhCommandRule;
    readonly matchedPath: readonly string[];
    readonly operands: readonly string[];
    readonly options: readonly ParsedGhOption[];
  }
  | { readonly kind: "invalid" };

const ROOT_VALUE_OPTIONS: readonly GhFlagGrammar[] = Object.freeze([
  Object.freeze({ long: "--repo", short: "-R", takesValue: true, forms: ["separate", "equals", "attached"] as const }),
  Object.freeze({ long: "--hostname", takesValue: true, forms: ["separate", "equals"] as const }),
]);

interface CommandForm {
  readonly words: readonly string[];
  readonly rule: GhCommandRule;
}

const COMMAND_FORMS = buildCommandForms();

export function parseGhCommandLine(args: readonly string[]): ParsedGhCommandLine {
  if (args.length === 1 && args[0] === "--version") return Object.freeze({ kind: "root-version" });
  if (args.length === 1 && args[0] === "--help") return Object.freeze({ kind: "root-help" });
  if (args[0] === "help") return parseHelpTopic(args.slice(1));
  if (args.length === 1 && GH_HELP_TOPIC_RULE_BY_NAME.has(args[0]!)) return parseHelpTopic(args);

  const words: string[] = [];
  const options: ParsedGhOption[] = [];
  let exact: CommandForm | undefined;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]!;
    if (argument === "--") {
      if (!exact) return Object.freeze({ kind: "invalid" });
      return commandResult(exact, words, args.slice(index), options);
    }
    if (argument.startsWith("-") && argument !== "-") {
      const parsed = parseOption(args, index, ROOT_VALUE_OPTIONS, "root");
      if (parsed) {
        options.push(parsed.option);
        index = parsed.lastIndex;
        continue;
      }
      if (!exact || hasLongerForm(words, exact.rule)) return Object.freeze({ kind: "invalid" });
      return commandResult(exact, words, args.slice(index), options);
    }

    const candidate = [...words, argument];
    const possible = COMMAND_FORMS.filter((form) => isPrefix(candidate, form.words));
    if (possible.length === 0) {
      if (!exact) return Object.freeze({ kind: "invalid" });
      return commandResult(exact, words, args.slice(index), options);
    }
    words.push(argument);
    exact = possible.find((form) => form.words.length === words.length) ?? exact;
  }

  return exact ? commandResult(exact, words, [], options) : Object.freeze({ kind: "invalid" });
}

export function ghCommandGrammarMatches(parsed: Extract<ParsedGhCommandLine, { kind: "command" }>): boolean {
  const rule = parsed.rule;
  if (parsed.operands.length < rule.operands.minimum || parsed.operands.length > rule.operands.maximum) return false;
  if (rule.operands.values && parsed.operands.some((operand) => !rule.operands.values!.includes(operand))) return false;
  const counts = new Map<string, number>();
  for (const option of parsed.options) {
    const grammar = rule.flags.find((flag) => option.identity === flag.long || option.identity === flag.short);
    if (!grammar) return false;
    const count = (counts.get(option.identity) ?? 0) + 1;
    if (count > 1 && !grammar.repeatable) return false;
    counts.set(option.identity, count);
    if (grammar.values && (!option.value || !grammar.values.includes(option.value))) return false;
  }
  return rule.flags.every((flag) => !flag.required || [...counts.keys()].some((name) => name === flag.long || name === flag.short));
}

export function isGhPrCreateCommand(args: readonly string[]): boolean {
  const parsed = parseGhCommandLine(args);
  return parsed.kind === "command" && parsed.rule.path.join(" ") === "pr create";
}

/** Validate the exact non-interactive PR creation grammar and return its targets. */
export function ghPrCreateRepositoryValues(args: readonly string[]): readonly string[] | undefined {
  const parsed = parseGhCommandLine(args);
  if (parsed.kind !== "command" || parsed.rule.path.join(" ") !== "pr create" || parsed.operands.length > 0) return undefined;

  const repositories: string[] = [];
  const counts = new Map<string, number>();
  const repeatable = new Set(["--reviewer", "--assignee", "--label", "--project"]);
  const unsafe = new Set(["--body-file", "--editor", "--web", "--recover", "--template", "--dry-run", "--attach"]);
  const identities = new Map<string, string>([
    ["-R", "--repo"], ["-d", "--draft"], ["-t", "--title"], ["-b", "--body"], ["-F", "--body-file"],
    ["-B", "--base"], ["-H", "--head"], ["-e", "--editor"], ["-w", "--web"], ["-f", "--fill"],
    ["-r", "--reviewer"], ["-a", "--assignee"], ["-l", "--label"], ["-p", "--project"], ["-m", "--milestone"],
    ["-T", "--template"],
  ]);

  for (const option of parsed.options) {
    const identity = identities.get(option.identity) ?? option.identity;
    const grammar = parsed.rule.flags.find((flag) => identity === flag.long);
    if (!grammar || (grammar.takesValue && option.value === undefined)) return undefined;
    if (unsafe.has(identity)) return undefined;
    const count = (counts.get(identity) ?? 0) + 1;
    if (count > 1 && !repeatable.has(identity)) return undefined;
    counts.set(identity, count);
    if (identity === "--repo") {
      if (option.value === undefined) return undefined;
      repositories.push(option.value);
    }
  }

  const fillModes = ["--fill", "--fill-first", "--fill-verbose"].filter((name) => counts.has(name));
  if (fillModes.length > 1) return undefined;
  if (fillModes.length === 0 && !(counts.has("--title") && counts.has("--body"))) return undefined;
  return Object.freeze(repositories);
}

export function isKnownGhTopLevel(name: string): boolean {
  return COMMAND_FORMS.some((form) => form.words[0] === name) || GH_HELP_TOPIC_RULE_BY_NAME.has(name) || name === "help";
}

/** A configured alias can be installed beneath any native command group. */
export function hasUnknownNestedGhCommand(args: readonly string[]): boolean {
  const parsed = parseGhCommandLine(args);
  return parsed.kind === "command" && parsed.rule.kind === "group" && parsed.operands.length > 0;
}

/** All native forms, including aliases inherited from aliased parent commands. */
export function ghNativeAliasesForRule(rule: GhCommandRule): readonly (readonly string[])[] {
  const canonical = rule.path.join(" ");
  const aliases = new Map<string, readonly string[]>();
  for (const form of COMMAND_FORMS) {
    if (form.rule !== rule || form.words.join(" ") === canonical) continue;
    aliases.set(form.words.join(" "), form.words);
  }
  return Object.freeze([...aliases.values()].sort((left, right) => left.join(" ").localeCompare(right.join(" "))));
}

function parseHelpTopic(args: readonly string[]): ParsedGhCommandLine {
  if (args.length !== 1) return Object.freeze({ kind: "invalid" });
  const rule = GH_HELP_TOPIC_RULE_BY_NAME.get(args[0]!);
  return rule
    ? Object.freeze({ kind: "help-topic", topic: rule.name, disposition: rule.disposition })
    : Object.freeze({ kind: "invalid" });
}

function commandResult(
  exact: CommandForm,
  consumedWords: readonly string[],
  remaining: readonly string[],
  rootOptions: readonly ParsedGhOption[],
): ParsedGhCommandLine {
  const pathLength = exact.words.length;
  const operands = [...consumedWords.slice(pathLength), ...remaining];
  const commandOptions: ParsedGhOption[] = [];
  const positional: string[] = [];
  for (let index = 0; index < operands.length; index++) {
    const argument = operands[index]!;
    if (argument === "--") {
      commandOptions.push(Object.freeze({ identity: "--", spelling: "--", position: index, scope: "command" }));
      positional.push(...operands.slice(index + 1));
      break;
    }
    if (!argument.startsWith("-") || argument === "-") {
      positional.push(argument);
      continue;
    }
    const parsed = parseOption(operands, index, exact.rule.flags, "command");
    if (!parsed) {
      commandOptions.push(Object.freeze({ identity: argument, spelling: argument, position: index, scope: "command" }));
      continue;
    }
    commandOptions.push(parsed.option);
    index = parsed.lastIndex;
  }
  return Object.freeze({
    kind: "command",
    rule: exact.rule,
    matchedPath: exact.words,
    operands: Object.freeze(positional),
    options: Object.freeze([...rootOptions, ...commandOptions]),
  });
}

function parseOption(
  args: readonly string[],
  index: number,
  grammar: readonly GhFlagGrammar[],
  scope: ParsedGhOption["scope"],
): { readonly option: ParsedGhOption; readonly lastIndex: number } | undefined {
  const argument = args[index]!;
  for (const flag of grammar) {
    for (const identity of [flag.long, flag.short].filter((value): value is string => !!value)) {
      if (argument === identity) {
        if (!flag.takesValue) return {
          option: Object.freeze({ identity, spelling: argument, position: index, scope }),
          lastIndex: index,
        };
        if (!flag.forms.includes("separate")) continue;
        const value = args[index + 1];
        if (!value || value.startsWith("-")) return undefined;
        return {
          option: Object.freeze({ identity, spelling: argument, value, position: index, scope }),
          lastIndex: index + 1,
        };
      }
      if (flag.forms.includes("equals") && argument.startsWith(`${identity}=`)) {
        const value = argument.slice(identity.length + 1);
        if (!value) return undefined;
        return {
          option: Object.freeze({ identity, spelling: argument.slice(0, identity.length + 1), value, position: index, scope }),
          lastIndex: index,
        };
      }
      if (flag.forms.includes("attached") && identity.startsWith("-") && !identity.startsWith("--") && argument.startsWith(identity) && argument.length > identity.length) {
        const value = argument.slice(identity.length).replace(/^=/, "");
        if (!value) return undefined;
        return {
          option: Object.freeze({ identity, spelling: identity, value, position: index, scope }),
          lastIndex: index,
        };
      }
    }
  }
  return undefined;
}

function buildCommandForms(): readonly CommandForm[] {
  const direct = new Map<string, CommandForm>();
  for (const rule of GH_READ_ONLY_RULES) {
    addForm(direct, rule.path, rule);
    for (const alias of rule.aliases) addForm(direct, alias, rule);
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const rule of GH_READ_ONLY_RULES) {
      for (let prefixLength = 1; prefixLength < rule.path.length; prefixLength++) {
        const canonicalPrefix = rule.path.slice(0, prefixLength).join(" ");
        const parent = GH_READ_ONLY_RULES.find((candidate) => candidate.path.join(" ") === canonicalPrefix);
        if (!parent) continue;
        const parentForms = [...direct.values()].filter((form) => form.rule === parent);
        for (const parentForm of parentForms) {
          const words = [...parentForm.words, ...rule.path.slice(prefixLength)];
          const key = words.join(" ");
          if (!direct.has(key)) {
            addForm(direct, words, rule);
            changed = true;
          }
        }
      }
    }
  }
  return Object.freeze([...direct.values()].sort((left, right) => right.words.length - left.words.length));
}

function addForm(forms: Map<string, CommandForm>, words: readonly string[], rule: GhCommandRule): void {
  const key = words.join(" ");
  const previous = forms.get(key);
  if (previous && previous.rule !== rule) throw new Error(`duplicate gh command form: ${key}`);
  forms.set(key, Object.freeze({ words: Object.freeze([...words]), rule }));
}

function hasLongerForm(words: readonly string[], rule: GhCommandRule): boolean {
  return COMMAND_FORMS.some((form) => form.rule !== rule && form.words.length > words.length && isPrefix(words, form.words));
}

function isPrefix(prefix: readonly string[], value: readonly string[]): boolean {
  return prefix.length <= value.length && prefix.every((word, index) => word === value[index]);
}
