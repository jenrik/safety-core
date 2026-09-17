import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

const TARGET = Object.freeze({
  version: "2.100.0",
  tag: "v2.100.0",
  commit: "45437bc7eeeb3359bbfddd1742f79de7652fd3e2",
  capturedAt: "2026-09-16",
  source: "https://github.com/cli/cli/tree/45437bc7eeeb3359bbfddd1742f79de7652fd3e2",
});

const HIDDEN_COMMANDS = Object.freeze([
  "accessibility",
  "actions",
  "attestation inspect",
  "auth git-credential",
  "codespace select",
  "credits",
  "repo credits",
  "repo garden",
  "send-telemetry",
  "version",
]);
const HIDDEN_COMMAND_ALIASES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  accessibility: Object.freeze(["a11y"]),
});
const EXECUTABLE_HELP_SECTION_ENTRIES = new Set(["accessibility", "actions"]);

const OFFICIAL_EXTENSION_STUBS = Object.freeze(["aw", "stack", "webhook"]);

type EntryKind = "command" | "group" | "top-level-command" | "hidden-command";

interface ReferenceEntry {
  readonly path: readonly string[];
  readonly usage: string;
  readonly summary: string;
  readonly aliases: readonly (readonly string[])[];
  readonly kind: EntryKind;
  readonly preview: boolean;
}

interface MutableEntry {
  path: string[];
  usage: string;
  summary: string;
  aliases: string[][];
  depth: number;
  preview: boolean;
}

const args = parseArguments(process.argv.slice(2));
const binaryInput = args.gh ?? Bun.which("gh");
if (!binaryInput) fail("gh was not found; pass --gh /path/to/gh");
const binary = resolve(binaryInput);

const temporary = mkdtempSync(`${tmpdir()}/safety-core-gh-reference-`);
try {
  const configDir = `${temporary}/config`;
  mkdirSync(configDir, { recursive: true });
  writeFileSync(`${configDir}/config.yml`, [
    "version: 1",
    "git_protocol: https",
    "prompt: disabled",
    "prefer_editor_prompt: disabled",
    "pager: cat",
    "aliases: {}",
    "color_labels: disabled",
    "accessible_colors: disabled",
    "accessible_prompter: disabled",
    "spinner: disabled",
    "telemetry: disabled",
    "",
  ].join("\n"));

  const environment = Object.freeze({
    HOME: `${temporary}/home`,
    XDG_CONFIG_HOME: `${temporary}/xdg-config`,
    XDG_DATA_HOME: `${temporary}/xdg-data`,
    GH_CONFIG_DIR: configDir,
    GH_PAGER: "cat",
    GH_PROMPT_DISABLED: "1",
    GH_NO_UPDATE_NOTIFIER: "1",
    GH_NO_EXTENSION_UPDATE_NOTIFIER: "1",
    GH_TELEMETRY: "false",
    NO_COLOR: "1",
    CLICOLOR: "0",
    TERM: "dumb",
  });

  const version = await capture(binary, ["version"], environment);
  if (!version.startsWith(`gh version ${TARGET.version} `)) {
    fail(`expected GitHub CLI ${TARGET.version}, got ${JSON.stringify(version.split("\n")[0])}`);
  }

  const reference = await stableCapture(binary, ["help", "reference"], environment);
  const environmentHelp = await stableCapture(binary, ["help", "environment"], environment);
  const rootHelp = await stableCapture(binary, ["help"], environment);
  const visible = parseReference(reference);
  const helpTopics = parseHelpTopics(rootHelp);
  const documentedEnvironment = parseEnvironmentRoutes(environmentHelp);
  const visiblePaths = new Set(visible.map((entry) => entry.path.join(" ")));
  for (const hidden of HIDDEN_COMMANDS) {
    if (visiblePaths.has(hidden)) fail(`hidden command unexpectedly appeared in help reference: gh ${hidden}`);
  }

  const hidden = HIDDEN_COMMANDS.map((path): ReferenceEntry => Object.freeze({
    path: Object.freeze(path.split(" ")),
    usage: `gh ${path}`,
    summary: "Built-in route hidden from gh help reference",
    aliases: Object.freeze((HIDDEN_COMMAND_ALIASES[path] ?? []).map((alias) => Object.freeze(alias.split(" ")))),
    kind: "hidden-command",
    preview: false,
  }));
  const commands = [...visible, ...hidden].sort(compareEntries);
  validateCommands(commands);

  const withoutChecksum = {
    schemaVersion: 1,
    metadata: {
      ...TARGET,
      captureCommand: "gh help reference; gh help environment; gh help",
      referenceSha256: sha256(reference),
      environmentSha256: sha256(environmentHelp),
      rootHelpSha256: sha256(rootHelp),
    },
    commands,
    helpTopics,
    environment: documentedEnvironment,
    dynamicRoutes: [
      { kind: "configured-alias", route: "gh <alias>", rationale: "Aliases are loaded from mutable user configuration and are not native built-ins." },
      { kind: "shipped-default-alias", route: "gh co", rationale: "The fallback co alias uses the same mutable alias mechanism and is not a native Cobra alias." },
      { kind: "installed-extension", route: "gh <extension>", rationale: "Installed extensions are unreviewed external programs." },
      ...OFFICIAL_EXTENSION_STUBS.map((name) => ({
        kind: "official-extension-stub",
        route: `gh ${name}`,
        rationale: "This hidden route prompts to install an external GitHub-maintained extension.",
      })),
    ],
  };
  const fixture = {
    ...withoutChecksum,
    metadata: {
      ...withoutChecksum.metadata,
      fixtureSha256: sha256(canonicalJson(withoutChecksum)),
    },
  };
  const output = resolve(args.output ?? "data/gh-cli-2.100.0-reference.json");
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${canonicalJson(fixture)}\n`);
  console.log(`captured ${commands.length} command nodes to ${output}`);
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

function parseArguments(values: readonly string[]): { gh?: string; output?: string } {
  const parsed: { gh?: string; output?: string } = {};
  for (let index = 0; index < values.length; index++) {
    const name = values[index]!;
    if (name !== "--gh" && name !== "--output") fail(`unknown argument: ${name}`);
    const value = values[++index];
    if (!value) fail(`missing value for ${name}`);
    if (name === "--gh") parsed.gh = value;
    else parsed.output = value;
  }
  return parsed;
}

async function stableCapture(binary: string, command: readonly string[], environment: Readonly<Record<string, string>>): Promise<string> {
  const first = await capture(binary, command, environment);
  const second = await capture(binary, command, environment);
  if (first !== second) fail(`non-deterministic output from ${binary} ${command.join(" ")}`);
  return first;
}

async function capture(binary: string, command: readonly string[], environment: Readonly<Record<string, string>>): Promise<string> {
  const process = Bun.spawn([binary, ...command], { env: { ...environment }, stdout: "pipe", stderr: "pipe" });
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(process.stdout).text(),
    new Response(process.stderr).text(),
    process.exited,
  ]);
  if (exitCode !== 0 || stderr.length > 0) {
    fail(`${binary} ${command.join(" ")} failed with exit ${exitCode}: ${stderr.trim()}`);
  }
  return stdout;
}

function parseReference(reference: string): ReferenceEntry[] {
  const lines = reference.split("\n");
  const entries: MutableEntry[] = [];
  let current: MutableEntry | undefined;
  let aliases = false;
  for (const line of lines) {
    const heading = /^(#{2,4}) (gh .+)$/.exec(line);
    if (heading) {
      const depth = heading[1]!.length;
      const usage = heading[2]!;
      const words = usage.split(/\s+/);
      if (words[0] !== "gh" || words.length < depth) fail(`malformed reference heading: ${line}`);
      if (entries.at(-1) && depth > entries.at(-1)!.depth + 1) fail(`reference heading depth jumped at: ${line}`);
      current = {
        path: words.slice(1, depth),
        usage,
        summary: "",
        aliases: [],
        depth,
        preview: false,
      };
      entries.push(current);
      aliases = false;
      continue;
    }
    if (!current) continue;
    if (line === "Aliases") { aliases = true; continue; }
    if (aliases && line.startsWith("gh ")) {
      current.aliases.push(...line.split(/,\s*/).map((value) => value.trim().split(/\s+/).slice(1)));
      aliases = false;
      continue;
    }
    if (!current.summary && line.length > 0 && !line.startsWith(" ")) {
      current.summary = line;
      current.preview = /\(preview\)/i.test(line);
    }
  }

  return entries.map((entry, index): ReferenceEntry => {
    const next = entries[index + 1];
    const hasChild = !!next && next.depth === entry.depth + 1;
    const kind: EntryKind = hasChild ? "group" : entry.depth === 2 ? "top-level-command" : "command";
    return Object.freeze({
      path: Object.freeze(entry.path),
      usage: entry.usage,
      summary: entry.summary,
      aliases: Object.freeze(entry.aliases.map((alias) => Object.freeze(alias))),
      kind,
      preview: entry.preview,
    });
  });
}

function parseHelpTopics(help: string): readonly { readonly name: string; readonly summary: string; readonly executable: true }[] {
  const lines = help.split("\n");
  const start = lines.indexOf("HELP TOPICS");
  if (start === -1) fail("gh help did not contain HELP TOPICS");
  const topics = [];
  for (const line of lines.slice(start + 1)) {
    if (line.length === 0) {
      if (topics.length > 0) break;
      continue;
    }
    const match = /^  ([a-z0-9-]+):\s+(.+)$/.exec(line);
    if (!match) fail(`malformed help topic: ${line}`);
    if (!EXECUTABLE_HELP_SECTION_ENTRIES.has(match[1]!)) {
      topics.push(Object.freeze({ name: match[1]!, summary: match[2]!, executable: true as const }));
    }
  }
  return Object.freeze(topics.sort((left, right) => compareText(left.name, right.name)));
}

function parseEnvironmentRoutes(help: string): readonly { readonly name: string }[] {
  const names = new Set<string>();
  for (const line of help.split("\n")) {
    const leadingNames = /^((?:`[A-Za-z_][A-Za-z0-9_]*`(?:,\s*)?)+)(?: \([^)]*\))?:/.exec(line);
    if (leadingNames) {
      for (const match of leadingNames[1]!.matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) names.add(match[1]!);
    }
    for (const match of line.matchAll(/\$(AppData|[A-Z][A-Z0-9_]*)\b/g)) names.add(match[1]!);
  }
  return Object.freeze([...names].sort(compareText).map((name) => Object.freeze({ name })));
}

function validateCommands(commands: readonly ReferenceEntry[]): void {
  const paths = new Set<string>();
  const aliases = new Set<string>();
  for (const command of commands) {
    const path = command.path.join(" ");
    if (paths.has(path)) fail(`duplicate command path: gh ${path}`);
    paths.add(path);
    for (const aliasParts of command.aliases) {
      const alias = aliasParts.join(" ");
      if (aliases.has(alias)) fail(`duplicate native alias: gh ${alias}`);
      aliases.add(alias);
    }
  }
  for (const alias of aliases) if (paths.has(alias)) fail(`native alias collides with canonical path: gh ${alias}`);
}

function compareEntries(left: ReferenceEntry, right: ReferenceEntry): number {
  return compareText(left.path.join("\0"), right.path.join("\0"));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function fail(message: string): never {
  throw new Error(message);
}
