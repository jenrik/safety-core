// Shell parsing for the LLM safety hook.
//
// Uses tree-sitter-bash for accurate shell parsing. Callers must initialize
// it before policy evaluation; an unavailable parser yields a parse failure.

import { statSync } from "node:fs";
import { Language, Node as SyntaxNode, Parser } from "web-tree-sitter";
import type {
  BashAssignment,
  BashCommand,
  BashFunction,
  BashGroup,
  BashIf,
  BashList,
  BashParseFailure,
  BashPipeline,
  BashProgram,
  BashRedirect,
  BashStatement,
  BashSubshell,
  BashWord,
  SourceSpan,
} from "./bash/cst.js";

// ─── Parser initialisation ──────────────────────────────────────────────────

let bashParser: Parser | null = null;
let initPromise: Promise<void> | null = null;

/**
 * Initialise the tree-sitter bash parser. Must be called once before
 * parsing. `wasmDir` should point to a directory containing:
 *   - tree-sitter-bash.wasm        (the bash grammar)
 *   - node_modules/web-tree-sitter/web-tree-sitter.wasm   (the runtime)
 *
 * Idempotent — subsequent calls return the existing parser.
 */
export async function initBashParser(wasmDir: string, grammarPath = `${wasmDir}/tree-sitter-bash.wasm`): Promise<void> {
  if (bashParser) return;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    // Initialise the tree-sitter runtime, pointing at our bundled WASM.
    await Parser.init({
      locateFile(): string {
        return `${wasmDir}/node_modules/web-tree-sitter/web-tree-sitter.wasm`;
      },
    });

    const BashLang = await Language.load(
      grammarPath,
    );
    bashParser = new Parser();
    bashParser.setLanguage(BashLang);
  })();

  return initPromise;
}

/** True once the Bash AST parser is available for policy checks. */
export function isBashParserInitialized(): boolean {
  return bashParser !== null;
}

/**
 * Discover the WASM directory from the path of the calling module
 * (usually `import.meta.url`). Walks up from `moduleUrl` looking for
 * the characteristic files, stopping at the directory root or filesystem
 * boundary.
 *
 * Layout assumptions (both in Nix store and esbuild bundle):
 *   <root>/
 *     tree-sitter-bash.wasm
 *     node_modules/web-tree-sitter/web-tree-sitter.wasm
 */
export function discoverWasmDir(moduleUrl: string): string {
  const { pathname, protocol } = new URL(moduleUrl);
  if (protocol !== "file:") {
    // Fallback for non-file URLs (shouldn't happen in practice).
    return pathname.slice(0, pathname.lastIndexOf("/"));
  }

  // Walk up from the module file looking for the directory that contains
  // tree-sitter-bash.wasm.  The layout always places this WASM at the root.
  let dir = pathname;
  // Strip filename, getting the directory.
  const slash = dir.lastIndexOf("/");
  if (slash > 0) dir = dir.slice(0, slash);

  for (let i = 0; i < 10; i++) {
    if (!dir || dir === "/") break;
    // This directory is the root if it contains tree-sitter-bash.wasm.
    // node_modules/ is always a sibling at the same root, but we use
    // tree-sitter-bash.wasm as the sentinel file since it's at the root
    // level and never inside node_modules/.
    try {
      statSync(`${dir}/tree-sitter-bash.wasm`);
      return dir;
    } catch {
      // Not in this directory; walk up.
    }
    dir = dir.slice(0, dir.lastIndexOf("/"));
  }

  // Fallback: return the module's own directory.
  const fallback = pathname.slice(0, pathname.lastIndexOf("/"));
  return fallback || "/";
}

// ─── Public types ───────────────────────────────────────────────────────────

// TODO: Remove the legacy flattened SimpleCommand/Redirect API and its
// projection helpers; CST programs and configured evaluation are the API.

export interface SimpleCommand {
  /** The command name (e.g. "cat", "kubectl", "curl"). */
  name: string;
  /** Positional arguments and flags after the command name. */
  args: string[];
  /** I/O redirects attached to this command. */
  redirects: Redirect[];
}

export type RedirectKind = "input" | "output" | "append";

export interface Redirect {
  kind: RedirectKind;
  /** The file/destination path. */
  target: string;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Parse a shell command string and extract all simple commands from it.
 *
 * Handles `&&`, `||`, `;`, `|`, `&` separators, redirects (`<`, `>`, `>>`),
 * and environment variable assignments (`FOO=bar cmd`). Returns an empty
 * array if the parser is not initialised or the command cannot be parsed.
 */
export function parseBash(command: string): SimpleCommand[] {
  const program = parseBashProgram(command);
  return program.kind === "parse-failure" ? [] : flattenCommands(program.statements);
}

/**
 * Parse Bash into an immutable, backend-neutral projection of the CST.
 *
 * The returned data never retains a web-tree-sitter node, allowing future
 * parser backends to produce the same model for the authorization walker.
 */
export function parseBashProgram(source: string): BashProgram | BashParseFailure {
  if (!bashParser) {
    return freeze({
      kind: "parse-failure",
      reason: "Bash parser is unavailable",
      span: { start: 0, end: source.length },
    });
  }

  const tree = bashParser.parse(source);
  const error = findSyntaxError(tree.rootNode);
  if (error) {
    return freeze({
      kind: "parse-failure",
      reason: `Bash parse error at ${error.startIndex}`,
      span: span(error),
    });
  }

  return freeze({
    kind: "program",
    source,
    statements: tree.rootNode.namedChildren.map(projectStatement),
  });
}

// ─── Utility helpers (pure string functions, no parser needed) ──────────────

/** Return the final path component (no trailing slash handling needed). */
export function basename(path: string): string {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "";
}

/** Match a filename against fnmatch-style globs (`*` matches anything). */
export function matchesAnyGlob(name: string, patterns: readonly string[]): boolean {
  const lower = name.toLowerCase();
  return patterns.some((pattern) => {
    const source =
      "^" +
      pattern
        .toLowerCase()
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*") +
      "$";
    return new RegExp(source).test(lower);
  });
}

/** Decode literal quote concatenation and shell escapes in a static word. */
export function stripQuotes(token: string): string {
  return decodeAnsiCQuotes(token)
    .replace(/\\\r?\n/g, "")
    .replaceAll("'", "")
    .replaceAll('"', "")
    .replace(/\\([\s\S])/g, "$1");
}

/** Decode Bash's static $'...' quoting form for command-policy matching. */
function decodeAnsiCQuotes(token: string): string {
  return token.replace(/\$'((?:\\[\s\S]|[^'])*)'/g, (_match, content: string) =>
    content.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{1,3}|[\s\S])/g, (_escape, value: string) => {
      if (/^x[0-9a-fA-F]+$/.test(value)) return String.fromCharCode(Number.parseInt(value.slice(1), 16));
      if (/^u[0-9a-fA-F]{4}$/.test(value) || /^U[0-9a-fA-F]{8}$/.test(value)) {
        return String.fromCodePoint(Number.parseInt(value.slice(1), 16));
      }
      if (/^[0-7]{1,3}$/.test(value)) return String.fromCharCode(Number.parseInt(value, 8));
      return ({ a: "\u0007", b: "\b", e: "\u001b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v" } as Record<string, string>)[value] ?? value;
    }),
  );
}

// ─── Internal tree-sitter projection helpers ────────────────────────────────

function projectStatement(node: SyntaxNode): BashStatement {
  switch (node.type) {
    case "command":
      return projectCommand(node, []);
    case "variable_assignment":
      return {
        kind: "command",
        assignments: [projectAssignment(node)],
        words: [],
        redirects: [],
        span: span(node),
      };
    case "redirected_statement":
      return projectRedirectedStatement(node);
    case "file_redirect":
      return {
        kind: "command",
        assignments: [],
        words: [],
        redirects: [projectRedirect(node)],
        span: span(node),
      };
    case "function_definition":
      return projectFunction(node);
    case "list":
      return projectList(node);
    case "pipeline":
      return {
        kind: "pipeline",
        statements: node.namedChildren.map(projectStatement),
        negated: node.children.some((child) => child.type === "!"),
        span: span(node),
      };
    case "subshell":
      return { kind: "subshell", statements: node.namedChildren.map(projectStatement), span: span(node) };
    case "compound_statement":
      return projectGroup(node);
    case "if_statement":
      return projectIf(node);
    default:
      return projectUnsupported(node);
  }
}

/** Flatten homogeneous left-recursive lists; mixed operators retain their control-flow tree. */
function projectList(node: SyntaxNode): BashList {
  const frames: Array<{
    readonly operator: "&&" | "||";
    readonly right: SyntaxNode;
    readonly span: SourceSpan;
  }> = [];
  let current = node;
  while (current.type === "list") {
    const operands = current.namedChildren.filter((child) => child.type !== "comment");
    const left = operands[0];
    const right = operands.at(-1);
    const operator = current.children.find((child) => child.type === "&&" || child.type === "||");
    if (!left || !right || !operator) break;
    frames.push({ operator: operator.type as "&&" | "||", right, span: span(current) });
    current = left;
  }
  const ordered = frames.reverse();
  if (ordered.length > 0 && ordered.every((frame) => frame.operator === ordered[0]!.operator)) {
    return {
      kind: "list",
      statements: [projectStatement(current), ...ordered.map((frame) => projectStatement(frame.right))],
      operators: ordered.map((frame) => frame.operator),
      span: span(node),
    };
  }
  let projected = projectStatement(current);
  for (const frame of ordered) {
    projected = {
      kind: "list",
      statements: [projected, projectStatement(frame.right)],
      operators: [frame.operator],
      span: frame.span,
    };
  }
  return projected as BashList;
}

function projectRedirectedStatement(node: SyntaxNode): BashStatement {
  const body = node.childForFieldName("body") ?? node.namedChildren.find((child) => child.type !== "file_redirect");
  if (!body) {
    return {
      kind: "command",
      assignments: [],
      words: [],
      redirects: node.childrenForFieldName("redirect").map(projectRedirect),
      span: span(node),
    };
  }

  const statement = projectStatement(body);
  return withRedirects(statement, node.childrenForFieldName("redirect").map(projectRedirect), span(node));
}

function projectCommand(node: SyntaxNode, redirects: readonly BashRedirect[]): BashCommand {
  const nameNode = node.childForFieldName("name");
  const commandName = nameNode?.namedChildren[0] ?? null;
  return {
    kind: "command",
    assignments: node.namedChildren.filter((child) => child.type === "variable_assignment").map(projectAssignment),
    words: [
      ...(commandName ? [projectWord(commandName)] : []),
      ...node.childrenForFieldName("argument").map(projectWord),
    ],
    redirects,
    span: span(node),
  };
}

function projectAssignment(node: SyntaxNode): BashAssignment {
  const name = node.childForFieldName("name");
  const value = node.childForFieldName("value");
  return {
    name: name?.text ?? "",
    value: value ? projectWord(value) : null,
    span: span(node),
  };
}

function projectRedirect(node: SyntaxNode): BashRedirect {
  const words = node.childrenForFieldName("destination").map(projectWord);
  return {
    kind: redirectKind(node) ?? "unsupported",
    target: words[0] ?? null,
    words,
    span: span(node),
  };
}

function projectFunction(node: SyntaxNode): BashFunction {
  const name = node.namedChildren.find((child) => child.type === "word");
  const bodyNode = node.namedChildren.find((child) => child !== name);
  const body = bodyNode
    ? projectStatement(bodyNode)
    : { kind: "unsupported" as const, reason: "Function body is missing", statements: [], span: span(node) };
  return { kind: "function", name: name?.text ?? "", body, span: span(node) };
}

function projectGroup(node: SyntaxNode): BashGroup {
  return { kind: "group", statements: node.namedChildren.map(projectStatement), span: span(node) };
}

function projectIf(node: SyntaxNode): BashIf {
  const thenNode = node.children.find((child) => child.type === "then");
  const elseNode = node.namedChildren.find((child) => child.type === "else_clause");
  const condition = node.namedChildren
    .filter((child) => child.type !== "else_clause" && (!thenNode || child.endIndex <= thenNode.startIndex))
    .map(projectStatement);
  const consequent = node.namedChildren
    .filter((child) => child.type !== "else_clause" && (!thenNode || child.startIndex >= thenNode.endIndex))
    .map(projectStatement);
  const alternate = elseNode ? elseNode.namedChildren.map(projectStatement) : [];
  return { kind: "if", condition, consequent, alternate, span: span(node) };
}

function projectWord(node: SyntaxNode): BashWord {
  const shared = { text: node.text, span: span(node) };
  switch (node.type) {
    case "word":
    case "raw_string":
    case "ansi_c_string":
    case "number":
      return { kind: "word", ...shared };
    case "string":
      return node.namedChildren.length === 0
        ? { kind: "word", ...shared }
        : { kind: "concatenation", ...shared, parts: node.namedChildren.map(projectWord) };
    case "simple_expansion":
    case "expansion":
      return { kind: "expansion", ...shared, statements: projectNestedStatements(node) };
    case "command_substitution":
      return { kind: "command-substitution", ...shared, statements: node.namedChildren.map(projectStatement) };
    case "concatenation":
      return { kind: "concatenation", ...shared, parts: node.namedChildren.map(projectWord) };
    default:
      return {
        kind: "unsupported-word",
        ...shared,
        reason: `Unsupported Bash word syntax: ${node.type}`,
        statements: projectNestedStatements(node),
      };
  }
}

function flattenCommands(statements: readonly BashStatement[]): SimpleCommand[] {
  const commands: SimpleCommand[] = [];
  for (const statement of statements) flattenStatement(statement, commands);
  return commands;
}

function flattenStatement(statement: BashStatement, out: SimpleCommand[]): void {
  switch (statement.kind) {
    case "command": {
      const [name, ...args] = statement.words;
      if (name) {
        const canonicalName = canonicalCommandName(name.text);
        if (canonicalName) {
          out.push({
            name: canonicalName,
            args: args.map((word) => stripQuotes(word.text)).filter((argument) => argument !== ""),
            redirects: statement.redirects.flatMap((redirect) => {
              if (!redirect.target || redirect.kind === "unsupported") return [];
              const target = stripQuotes(redirect.target.text);
              return target ? [{ kind: redirect.kind, target }] : [];
            }),
          });
        }
      }
      flattenWordsInSourceOrder([
        ...statement.assignments.flatMap((assignment) => assignment.value ? [assignment.value] : []),
        ...statement.words,
        ...statement.redirects.flatMap((redirect) => redirect.words),
      ], out);
      break;
    }
    case "function":
      flattenStatement(statement.body, out);
      flattenRedirects(statement.redirects, out);
      break;
    case "list":
    case "pipeline":
    case "subshell":
    case "group":
      for (const child of statement.statements) flattenStatement(child, out);
      flattenRedirects(statement.redirects, out);
      break;
    case "if":
      for (const child of [...statement.condition, ...statement.consequent, ...statement.alternate]) flattenStatement(child, out);
      flattenRedirects(statement.redirects, out);
      break;
    case "unsupported":
      for (const child of statement.statements) flattenStatement(child, out);
      flattenRedirects(statement.redirects, out);
      break;
  }
}

function flattenWord(word: BashWord, out: SimpleCommand[]): void {
  if (word.kind === "command-substitution") {
    for (const statement of word.statements) flattenStatement(statement, out);
  } else if (word.kind === "concatenation") {
    for (const part of word.parts) flattenWord(part, out);
  } else if (word.kind === "expansion" || word.kind === "unsupported-word") {
    for (const statement of word.statements) flattenStatement(statement, out);
  }
}

function flattenRedirects(redirects: readonly BashRedirect[] | undefined, out: SimpleCommand[]): void {
  for (const redirect of redirects ?? []) {
    flattenWordsInSourceOrder(redirect.words, out);
  }
}

function flattenWordsInSourceOrder(words: readonly BashWord[], out: SimpleCommand[]): void {
  words
    .map((word, index) => ({ word, index }))
    .sort((left, right) => left.word.span.start - right.word.span.start || left.index - right.index)
    .forEach(({ word }) => flattenWord(word, out));
}

function projectUnsupported(node: SyntaxNode): BashStatement {
  return {
    kind: "unsupported",
    reason: `Unsupported Bash syntax: ${node.type}`,
    statements: projectNestedStatements(node),
    span: span(node),
  };
}

function projectNestedStatements(node: SyntaxNode): BashStatement[] {
  const statements: BashStatement[] = [];
  for (const child of node.namedChildren) {
    if (isProjectableStatement(child)) {
      statements.push(projectStatement(child));
    } else {
      statements.push(...projectNestedStatements(child));
    }
  }
  return statements;
}

function isProjectableStatement(node: SyntaxNode): boolean {
  return [
    "command",
    "redirected_statement",
    "function_definition",
    "list",
    "pipeline",
    "subshell",
    "compound_statement",
    "if_statement",
  ].includes(node.type);
}

function withRedirects(statement: BashStatement, redirects: readonly BashRedirect[], statementSpan: SourceSpan): BashStatement {
  switch (statement.kind) {
    case "command":
      return { ...statement, redirects, span: statementSpan };
    case "function":
    case "list":
    case "pipeline":
    case "subshell":
    case "group":
    case "if":
    case "unsupported":
      return { ...statement, redirects, span: statementSpan };
  }
}

function findSyntaxError(node: SyntaxNode): SyntaxNode | null {
  if (node.isError || node.isMissing) return node;
  for (const child of node.children) {
    const error = findSyntaxError(child);
    if (error) return error;
  }
  return null;
}

function span(node: SyntaxNode): SourceSpan {
  return { start: node.startIndex, end: node.endIndex };
}

function freeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Shell quotes do not alter an executable name (`g''h` still runs `gh`). */
function canonicalCommandName(text: string): string {
  return basename(stripQuotes(text));
}

/** Infer whether a file_redirect is input, output, or append from its text. */
function redirectKind(node: SyntaxNode): RedirectKind | null {
  const text = node.text;
  if (text.includes("<")) return "input";
  if (text.includes(">>")) return "append";
  if (text.includes(">")) return "output";
  return null;
}
