// Shell parsing for the LLM safety hook.
//
// Uses tree-sitter-bash for accurate shell parsing. Parser initialization is a
// deployment boundary; policy evaluation must never silently run without it.

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
let initializationFailure: BashParserFailure | null = null;

export class BashParserFailure extends Error {
  readonly code = "SAFETY_CORE_BASH_PARSER_FAILURE";

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BashParserFailure";
  }
}

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
    try {
      // Initialise the tree-sitter runtime, pointing at our bundled WASM.
      await Parser.init({
        locateFile(): string {
          return `${wasmDir}/node_modules/web-tree-sitter/web-tree-sitter.wasm`;
        },
      });

      const BashLang = await Language.load(grammarPath);
      bashParser = new Parser();
      bashParser.setLanguage(BashLang);
    } catch (cause) {
      initializationFailure = new BashParserFailure(
        "Bash parser initialization failed; safety-core cannot start without its packaged parser",
        { cause },
      );
      throw initializationFailure;
    }
  })();

  return initPromise;
}

/** True once the Bash AST parser is available for policy checks. */
export function isBashParserInitialized(): boolean {
  return bashParser !== null;
}

/** Crash rather than evaluating restrictive policy with no parser. */
export function assertBashParserInitialized(): asserts bashParser is Parser {
  if (bashParser) return;
  throw initializationFailure ?? new BashParserFailure(
    "Bash parser was not initialized before safety-core policy evaluation",
  );
}

export function isBashParserFailure(error: unknown): error is BashParserFailure {
  return error instanceof BashParserFailure
    || (typeof error === "object" && error !== null
      && "code" in error && error.code === "SAFETY_CORE_BASH_PARSER_FAILURE");
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

type RedirectKind = "input" | "output" | "append";

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Parse Bash into an immutable, backend-neutral projection of the CST.
 *
 * The returned data never retains a web-tree-sitter node, allowing future
 * parser backends to produce the same model for the authorization walker.
 */
export function parseBashProgram(source: string): BashProgram | BashParseFailure {
  assertBashParserInitialized();

  const tree = bashParser.parse(source);
  const error = findSyntaxError(tree.rootNode);
  const executorCompounds = recoverExecutorCompounds(tree.rootNode, source);
  if (error && executorCompounds.size === 0 && !isRecoverableNamedCoprocSubshell(tree.rootNode, error, source)) {
    return freeze({
      kind: "parse-failure",
      reason: `Bash parse error at ${error.startIndex}`,
      span: span(error),
    });
  }

  return freeze({
    kind: "program",
    source,
    statements: tree.rootNode.namedChildren.map((node) => projectStatement(node, executorCompounds)),
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

function projectStatement(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement> = new Map()): BashStatement {
  switch (node.type) {
    case "command":
      return projectCommand(node, [], executorCompounds.get(node.startIndex), executorCompounds);
    case "variable_assignment":
      return {
        kind: "command",
        assignments: [projectAssignment(node, executorCompounds)],
        words: [],
        redirects: [],
        span: span(node),
      };
    case "redirected_statement":
      return projectRedirectedStatement(node, executorCompounds);
    case "file_redirect":
      return {
        kind: "command",
        assignments: [],
        words: [],
        redirects: [projectRedirect(node, executorCompounds)],
        span: span(node),
      };
    case "function_definition":
      return projectFunction(node, executorCompounds);
    case "list":
      return projectList(node, executorCompounds);
    case "pipeline":
      return {
        kind: "pipeline",
        statements: node.namedChildren.map((child) => projectStatement(child, executorCompounds)),
        negated: node.children.some((child) => child.type === "!"),
        span: span(node),
      };
    case "subshell":
      return { kind: "subshell", statements: node.namedChildren.map((child) => projectStatement(child, executorCompounds)), span: span(node) };
    case "compound_statement":
      return projectGroup(node, executorCompounds);
    case "if_statement":
      return projectIf(node, executorCompounds);
    default:
      return projectUnsupported(node, executorCompounds);
  }
}

/** Flatten homogeneous left-recursive lists; mixed operators retain their control-flow tree. */
function projectList(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashList {
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
      statements: [projectStatement(current, executorCompounds), ...ordered.map((frame) => projectStatement(frame.right, executorCompounds))],
      operators: ordered.map((frame) => frame.operator),
      span: span(node),
    };
  }
  let projected = projectStatement(current, executorCompounds);
  for (const frame of ordered) {
    projected = {
      kind: "list",
      statements: [projected, projectStatement(frame.right, executorCompounds)],
      operators: [frame.operator],
      span: frame.span,
    };
  }
  return projected as BashList;
}

function projectRedirectedStatement(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashStatement {
  const body = node.childForFieldName("body") ?? node.namedChildren.find((child) => child.type !== "file_redirect");
  if (!body) {
    return {
      kind: "command",
      assignments: [],
      words: [],
      redirects: node.childrenForFieldName("redirect").map((child) => projectRedirect(child, executorCompounds)),
      span: span(node),
    };
  }

  const statement = projectStatement(body, executorCompounds);
  return withRedirects(statement, node.childrenForFieldName("redirect").map((child) => projectRedirect(child, executorCompounds)), span(node));
}

function projectCommand(
  node: SyntaxNode,
  redirects: readonly BashRedirect[],
  executorCompound?: BashStatement,
  executorCompounds: ReadonlyMap<number, BashStatement> = new Map(),
): BashCommand {
  const nameNode = node.childForFieldName("name");
  const commandName = nameNode?.namedChildren[0] ?? null;
  return {
    kind: "command",
    assignments: node.namedChildren.filter((child) => child.type === "variable_assignment").map((child) => projectAssignment(child, executorCompounds)),
    words: [
      ...(commandName ? [projectWord(commandName, executorCompounds)] : []),
      ...node.childrenForFieldName("argument").map((child) => projectWord(child, executorCompounds)),
      ...(executorCompound ? [{
        kind: "unsupported-word" as const,
        text: "",
        reason: "Retained executor compound body",
        statements: [executorCompound],
        span: executorCompound.span,
      }] : []),
    ],
    redirects,
    span: span(node),
  };
}

function projectAssignment(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement> = new Map()): BashAssignment {
  const name = node.childForFieldName("name");
  const value = node.childForFieldName("value");
  return {
    name: name?.text ?? "",
    value: value ? projectWord(value, executorCompounds) : null,
    span: span(node),
  };
}

function projectRedirect(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashRedirect {
  const words = node.childrenForFieldName("destination").map((child) => projectWord(child, executorCompounds));
  return {
    kind: redirectKind(node) ?? "unsupported",
    target: words[0] ?? null,
    words,
    span: span(node),
  };
}

function projectFunction(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashFunction {
  const name = node.namedChildren.find((child) => child.type === "word");
  const bodyNode = node.namedChildren.find((child) => child !== name);
  const body = bodyNode
    ? projectStatement(bodyNode, executorCompounds)
    : { kind: "unsupported" as const, reason: "Function body is missing", statements: [], span: span(node) };
  return { kind: "function", name: name?.text ?? "", body, span: span(node) };
}

function projectGroup(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashGroup {
  return { kind: "group", statements: node.namedChildren.map((child) => projectStatement(child, executorCompounds)), span: span(node) };
}

function projectIf(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashIf {
  const thenNode = node.children.find((child) => child.type === "then");
  const elseNode = node.namedChildren.find((child) => child.type === "else_clause");
  const condition = node.namedChildren
    .filter((child) => child.type !== "else_clause" && (!thenNode || child.endIndex <= thenNode.startIndex))
    .map((child) => projectStatement(child, executorCompounds));
  const consequent = node.namedChildren
    .filter((child) => child.type !== "else_clause" && (!thenNode || child.startIndex >= thenNode.endIndex))
    .map((child) => projectStatement(child, executorCompounds));
  const alternate = elseNode ? elseNode.namedChildren.map((child) => projectStatement(child, executorCompounds)) : [];
  return { kind: "if", condition, consequent, alternate, span: span(node) };
}

function projectWord(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement> = new Map()): BashWord {
  const shared = { text: node.text, span: span(node) };
  switch (node.type) {
    case "word":
    case "raw_string":
    case "ansi_c_string":
    case "number":
    case "string_content":
      return { kind: "word", ...shared };
    case "string":
      return node.namedChildren.length === 0
        ? { kind: "word", ...shared }
        : { kind: "concatenation", ...shared, parts: node.namedChildren.map((child) => projectWord(child, executorCompounds)) };
    case "simple_expansion":
    case "expansion":
      return { kind: "expansion", ...shared, statements: projectNestedStatements(node, executorCompounds) };
    case "command_substitution":
      return { kind: "command-substitution", ...shared, statements: node.namedChildren.map((child) => projectStatement(child, executorCompounds)) };
    case "concatenation":
      return { kind: "concatenation", ...shared, parts: node.namedChildren.map((child) => projectWord(child, executorCompounds)) };
    default:
      return {
        kind: "unsupported-word",
        ...shared,
        reason: `Unsupported Bash word syntax: ${node.type}`,
        statements: projectNestedStatements(node, executorCompounds),
      };
  }
}


function projectUnsupported(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashStatement {
  return {
    kind: "unsupported",
    reason: `Unsupported Bash syntax: ${node.type}`,
    statements: projectNestedStatements(node, executorCompounds),
    span: span(node),
  };
}

function projectNestedStatements(node: SyntaxNode, executorCompounds: ReadonlyMap<number, BashStatement>): BashStatement[] {
  const statements: BashStatement[] = [];
  for (const child of node.namedChildren) {
    if (isProjectableStatement(child)) {
      statements.push(projectStatement(child, executorCompounds));
    } else {
      statements.push(...projectNestedStatements(child, executorCompounds));
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

function isRecoverableNamedCoprocSubshell(root: SyntaxNode, error: SyntaxNode, source: string): boolean {
  if (!error.isMissing || error.type !== ";") return false;
  const statements = root.namedChildren.filter((child) => child.type !== "comment");
  if (statements.length !== 2 || statements[0]?.type !== "command" || statements[1]?.type !== "subshell") return false;
  const prefix = source.slice(statements[0].startIndex, statements[1].startIndex);
  return /^coproc\s+[A-Za-z_][A-Za-z0-9_]*\s*$/s.test(prefix);
}

function recoverExecutorCompounds(root: SyntaxNode, source: string): ReadonlyMap<number, BashStatement> {
  const prefixes: Array<{ readonly owner: number; readonly body: number }> = [];
  const visit = (node: SyntaxNode): void => {
    if (node.type === "command") {
      const suffix = source.slice(node.startIndex);
      const match = /^(?:time(?:[ \t]+-p)?|coproc(?:[ \t]+[A-Za-z_][A-Za-z0-9_]*)?)[ \t]+(?=(?:\(|\{|if\b|for\b|while\b|until\b|case\b))/s.exec(suffix);
      if (match) prefixes.push({ owner: node.startIndex, body: node.startIndex + match[0].length });
    }
    for (const child of node.namedChildren) visit(child);
  };
  visit(root);
  if (prefixes.length === 0) return new Map();

  const characters = source.split("");
  for (const prefix of prefixes) {
    for (let index = prefix.owner; index < prefix.body; index++) {
      if (characters[index] !== "\n" && characters[index] !== "\r") characters[index] = " ";
    }
  }
  const reparsed = bashParser!.parse(characters.join(""));
  if (findSyntaxError(reparsed.rootNode)) return new Map();

  const recovered = new Map<number, BashStatement>();
  for (const prefix of prefixes) {
    const body = statementStartingAt(reparsed.rootNode, prefix.body);
    if (body) recovered.set(prefix.owner, projectStatement(body));
  }
  return recovered;
}

function statementStartingAt(node: SyntaxNode, start: number): SyntaxNode | null {
  for (const child of node.namedChildren) {
    if (child.startIndex === start && (isProjectableStatement(child) || /_statement$/.test(child.type))) return child;
    if (child.startIndex <= start && child.endIndex >= start) {
      const nested = statementStartingAt(child, start);
      if (nested) return nested;
    }
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

/** Infer whether a file_redirect is input, output, or append from its text. */
function redirectKind(node: SyntaxNode): RedirectKind | null {
  const text = node.text;
  if (text.includes("<")) return "input";
  if (text.includes(">>")) return "append";
  if (text.includes(">")) return "output";
  return null;
}
