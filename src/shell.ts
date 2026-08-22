// Shell parsing for the LLM safety hook.
//
// Uses tree-sitter-bash for accurate shell parsing. Falls back to a simple
// regex tokenizer if the parser hasn't been initialised (e.g. in tests).

import { statSync } from "node:fs";
import { Language, Node as SyntaxNode, Parser } from "web-tree-sitter";

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
export async function initBashParser(wasmDir: string): Promise<void> {
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
      `${wasmDir}/tree-sitter-bash.wasm`,
    );
    bashParser = new Parser();
    bashParser.setLanguage(BashLang);
  })();

  return initPromise;
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
  if (!bashParser) return [];
  if (!command.trim()) return [];

  const tree = bashParser.parse(command);
  const commands: SimpleCommand[] = [];

  findCommands(tree.rootNode, commands);

  return commands;
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

/** Strip surrounding single or double quotes from a token. */
export function stripQuotes(token: string): string {
  return token.replace(/^['"]|['"]$/g, "");
}

// ─── Internal tree-sitter helpers ───────────────────────────────────────────

/** Recursively walk the AST, collecting SimpleCommand objects. */
function findCommands(node: SyntaxNode, out: SimpleCommand[]): void {
  if (node.type === "command") {
    const cmd = extractCommand(node);
    if (cmd) out.push(cmd);
    // Don't recurse into command children — they've already been handled.
    return;
  }

  for (const child of node.namedChildren) {
    findCommands(child, out);
  }
}

/** Extract a single SimpleCommand from a `command` AST node. */
function extractCommand(node: SyntaxNode): SimpleCommand | null {
  const nameNode = node.childForFieldName("name");
  if (!nameNode) return null;

  const name = basename(nameNode.text);
  if (!name) return null;

  // Collect arguments (skip env assignments passed as children of the command).
  const args: string[] = [];
  const argNodes = node.childrenForFieldName("argument");
  for (const arg of argNodes) {
    args.push(stripQuotes(arg.text));
  }

  // Collect redirects. Redirects can appear directly on the `command` node, or
  // the command may be wrapped in a `redirected_statement` one level up.
  const redirects: Redirect[] = [];
  collectRedirects(node, redirects);
  if (node.parent && node.parent.type === "redirected_statement") {
    collectRedirects(node.parent, redirects);
  }

  return {
    name,
    args: args.filter((a) => a !== ""),
    redirects,
  };
}

/** Collect file redirect nodes from `node` into `out`. */
function collectRedirects(node: SyntaxNode, out: Redirect[]): void {
  const redirectNodes = node.childrenForFieldName("redirect");
  for (const r of redirectNodes) {
    if (r.type !== "file_redirect") continue;

    // Determine the kind from the operator text that sits between children.
    const kind = redirectKind(r);
    if (!kind) continue;

    const destNodes = r.childrenForFieldName("destination");
    if (destNodes.length === 0) continue;

    const target = stripQuotes(destNodes[0].text);
    if (target) {
      out.push({ kind, target });
    }
  }
}

/** Infer whether a file_redirect is input, output, or append from its text. */
function redirectKind(node: SyntaxNode): RedirectKind | null {
  const text = node.text;
  if (text.includes("<")) return "input";
  if (text.includes(">>")) return "append";
  if (text.includes(">")) return "output";
  return null;
}
