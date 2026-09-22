import { createHash } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { PolicyStartupError, type ResolvedSessionPolicyConfig } from "./config.js";
import { validateLoadedBashPolicy } from "./evaluate.js";
import type { BashPolicyEvent, BashPolicySelector, LoadedBashPolicy, PolicyDecision, ValidatedBashPolicy } from "./types.js";
import { compilePolicyDocument } from "./dsl/compile.js";
import { createDslPolicy } from "./dsl/evaluate.js";
import { parsePolicyDocument } from "./dsl/validate.js";

export interface LoadedPolicySource {
  readonly canonicalPath: string;
  readonly scope: "global" | "project";
  readonly sha256: string;
}

export interface LoadedPolicySet {
  readonly policies: readonly ValidatedBashPolicy[];
  readonly sources: readonly LoadedPolicySource[];
}

export interface PolicyLoaderOptions {
  readonly importCodePolicy?: (url: string) => unknown | Promise<unknown>;
}

interface CodePolicyDefinition {
  readonly apiVersion: 1;
  readonly layer: "guard" | "permission";
  readonly select: readonly unknown[];
  evaluate(event: BashPolicyEvent): PolicyDecision;
}

/** Load every session source once, using canonical filesystem identity. */
export async function loadPolicySet(
  resolved: ResolvedSessionPolicyConfig,
  options: PolicyLoaderOptions = {},
): Promise<LoadedPolicySet> {
  return loadPolicySources(resolved.sources, options);
}

/** Load an explicit, already-resolved source manifest without consulting config. */
export async function loadPolicySources(
  references: readonly import("./config.js").ResolvedPolicySource[],
  options: PolicyLoaderOptions = {},
): Promise<LoadedPolicySet> {
  const importCodePolicy = options.importCodePolicy ?? ((url: string) => import(url));
  const sources: LoadedPolicySource[] = [];
  const policies: ValidatedBashPolicy[] = [];
  const seen = new Set<string>();

  for (const reference of references) {
    if (reference.scope === "project" && !reference.path.endsWith(".policy.json")) {
      throw new PolicyStartupError(reference.path, "trusted code policy sources are permitted only in global configuration");
    }
    const canonicalPath = canonicalizeSource(reference.path);
    if (seen.has(canonicalPath)) continue;
    seen.add(canonicalPath);
    const bytes = readSource(canonicalPath);
    const policy = canonicalPath.endsWith(".policy.mjs")
      ? reference.scope === "global"
        ? await loadCodePolicy(canonicalPath, bytes, importCodePolicy)
        : (() => { throw new PolicyStartupError(canonicalPath, "trusted code policy sources are permitted only in global configuration"); })()
      : canonicalPath.endsWith(".policy.json")
        ? loadDslPolicy(canonicalPath, bytes)
        : (() => { throw new PolicyStartupError(canonicalPath, `${reference.scope} policy source must use the exact ${reference.scope === "global" ? ".policy.mjs or .policy.json" : ".policy.json"} extension`); })();
    sources.push(Object.freeze({
      canonicalPath,
      scope: reference.scope,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    }));
    policies.push(policy);
  }

  return Object.freeze({ policies: Object.freeze(policies), sources: Object.freeze(sources) });
}

async function loadCodePolicy(path: string, bytes: Buffer, importCodePolicy: NonNullable<PolicyLoaderOptions["importCodePolicy"]>): Promise<ValidatedBashPolicy> {
  rejectRelativeRuntimeImports(path, bytes.toString("utf8"));
  return loadDefinition(path, await importDefinition(path, importCodePolicy));
}

function loadDslPolicy(path: string, bytes: Buffer): ValidatedBashPolicy {
  try {
    return validateLoadedBashPolicy(createDslPolicy(compilePolicyDocument(parsePolicyDocument(bytes.toString("utf8"))), path));
  } catch (error) {
    const detail = error instanceof Error ? `invalid DSL policy: ${error.message}` : "invalid DSL policy";
    throw new PolicyStartupError(path, detail, error);
  }
}

function canonicalizeSource(path: string): string {
  try {
    return realpathSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot canonicalize policy source", error);
  }
}

function readSource(path: string): Buffer {
  try {
    return readFileSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot read policy source", error);
  }
}

function rejectRelativeRuntimeImports(path: string, source: string): void {
  try {
    for (const specifier of moduleSpecifiers(source)) {
      if (specifier.startsWith(".") || specifier.startsWith("..")) {
        throw new PolicyStartupError(path, `relative runtime import is forbidden: ${specifier}`);
      }
    }
  } catch (error) {
    if (error instanceof PolicyStartupError) throw error;
    const detail = error instanceof Error ? `cannot scan policy source imports: ${error.message}` : "cannot scan policy source imports";
    throw new PolicyStartupError(path, detail, error);
  }
}

function moduleSpecifiers(source: string): readonly string[] {
  const specifiers: string[] = [];
  for (let index = 0; index < source.length;) {
    const character = source[index]!;
    if (character === "'" || character === '"') {
      index = skipQuoted(source, index);
      continue;
    }
    if (character === "`") {
      index = scanTemplate(source, index, specifiers);
      continue;
    }
    if (character === "/" && source[index + 1] === "/") {
      index = source.indexOf("\n", index + 2);
      if (index === -1) break;
      continue;
    }
    if (character === "/" && source[index + 1] === "*") {
      index = source.indexOf("*/", index + 2);
      if (index === -1) break;
      index += 2;
      continue;
    }
    if (!isIdentifierStart(character)) {
      index++;
      continue;
    }
    const wordEnd = readIdentifierEnd(source, index);
    const word = source.slice(index, wordEnd);
    if (word === "import" || word === "export") {
      const specifier = readModuleSpecifier(source, wordEnd, word === "import");
      if (specifier !== undefined) specifiers.push(specifier.value);
      index = specifier?.end ?? wordEnd;
      continue;
    }
    index = wordEnd;
  }
  return specifiers;
}

function readModuleSpecifier(source: string, index: number, isImport: boolean): { readonly value: string; readonly end: number } | undefined {
  index = skipTrivia(source, index);
  if (isImport && source[index] === ".") return undefined; // import.meta
  if (isImport && source[index] === "(") {
    return readQuotedSpecifier(source, skipTrivia(source, index + 1));
  }
  if (isImport && isQuote(source[index])) return readQuotedSpecifier(source, index);

  while (index < source.length && source[index] !== ";") {
    const afterTrivia = skipTrivia(source, index);
    if (afterTrivia !== index) {
      index = afterTrivia;
      continue;
    }
    if (isQuote(source[index])) {
      index = skipQuoted(source, index);
      continue;
    }
    if (isIdentifierStart(source[index]!)) {
      const wordEnd = readIdentifierEnd(source, index);
      if (source.slice(index, wordEnd) === "from") return readQuotedSpecifier(source, skipTrivia(source, wordEnd));
      index = wordEnd;
      continue;
    }
    index++;
  }
  return undefined;
}

function readQuotedSpecifier(source: string, index: number): { readonly value: string; readonly end: number } | undefined {
  if (!isQuote(source[index])) return undefined;
  const quote = source[index]!;
  let value = "";
  for (index++; index < source.length; index++) {
    const character = source[index]!;
    if (character === quote) return { value, end: index + 1 };
    if (character === "\\") {
      const escape = source[index + 1];
      if (escape === undefined) return undefined;
      value += decodeEscape(source, index + 1);
      index += escape === "u" && source[index + 2] === "{" ? source.indexOf("}", index + 3) - index : escape === "u" ? 5 : escape === "x" ? 3 : 1;
      continue;
    }
    value += character;
  }
  return undefined;
}

function decodeEscape(source: string, index: number): string {
  const character = source[index]!;
  if (character === "x") return decodeCodePoint(source.slice(index + 1, index + 3), 2);
  if (character === "u") {
    if (source[index + 1] === "{") {
      const end = source.indexOf("}", index + 2);
      return decodeCodePoint(end === -1 ? "" : source.slice(index + 2, end), undefined);
    }
    return decodeCodePoint(source.slice(index + 1, index + 5), 4);
  }
  return character;
}

function decodeCodePoint(encoded: string, exactLength: number | undefined): string {
  if ((exactLength !== undefined && encoded.length !== exactLength) || !/^[0-9A-Fa-f]+$/.test(encoded)) {
    throw new SyntaxError("invalid string escape in module specifier");
  }
  const value = Number.parseInt(encoded, 16);
  if (value > 0x10ffff) throw new SyntaxError("module specifier escape is outside the Unicode range");
  return String.fromCodePoint(value);
}

function skipTrivia(source: string, index: number): number {
  while (index < source.length) {
    if (/\s/.test(source[index]!)) {
      index++;
      continue;
    }
    if (source[index] === "/" && source[index + 1] === "/") {
      const lineEnd = source.indexOf("\n", index + 2);
      index = lineEnd === -1 ? source.length : lineEnd + 1;
      continue;
    }
    if (source[index] === "/" && source[index + 1] === "*") {
      const commentEnd = source.indexOf("*/", index + 2);
      index = commentEnd === -1 ? source.length : commentEnd + 2;
      continue;
    }
    break;
  }
  return index;
}

function skipQuoted(source: string, index: number): number {
  const quote = source[index]!;
  for (index++; index < source.length; index++) {
    if (source[index] === "\\") index++;
    else if (source[index] === quote) return index + 1;
  }
  return source.length;
}

function scanTemplate(source: string, index: number, specifiers: string[]): number {
  for (index++; index < source.length; index++) {
    if (source[index] === "\\") {
      index++;
      continue;
    }
    if (source[index] === "`") return index + 1;
    if (source[index] === "$" && source[index + 1] === "{") {
      const expressionStart = index + 2;
      const expressionEnd = findTemplateSubstitutionEnd(source, expressionStart);
      specifiers.push(...moduleSpecifiers(source.slice(expressionStart, expressionEnd)));
      index = expressionEnd;
    }
  }
  return source.length;
}

function findTemplateSubstitutionEnd(source: string, index: number): number {
  let depth = 1;
  let canStartRegularExpression = true;
  while (index < source.length) {
    if (source[index] === "'" || source[index] === '"') {
      index = skipQuoted(source, index);
      canStartRegularExpression = false;
      continue;
    }
    if (source[index] === "`") {
      index = skipTemplateLiteral(source, index);
      canStartRegularExpression = false;
      continue;
    }
    if (source[index] === "/" && source[index + 1] === "/") {
      const lineEnd = source.indexOf("\n", index + 2);
      index = lineEnd === -1 ? source.length : lineEnd + 1;
      continue;
    }
    if (source[index] === "/" && source[index + 1] === "*") {
      const commentEnd = source.indexOf("*/", index + 2);
      index = commentEnd === -1 ? source.length : commentEnd + 2;
      continue;
    }
    if (source[index] === "/") {
      if (canStartRegularExpression) {
        index = skipRegularExpression(source, index);
        canStartRegularExpression = false;
        continue;
      }
      canStartRegularExpression = true;
      index++;
      continue;
    }
    if (source[index] === "{") {
      depth++;
      canStartRegularExpression = true;
      index++;
      continue;
    }
    if (source[index] === "}") {
      if (--depth === 0) return index;
      canStartRegularExpression = false;
      index++;
      continue;
    }
    if (source[index] === ")" || source[index] === "]") {
      canStartRegularExpression = false;
      index++;
      continue;
    }
    if (source[index] === "(" || source[index] === "[") {
      canStartRegularExpression = true;
      index++;
      continue;
    }
    if (isIdentifierStart(source[index]!)) {
      const end = readIdentifierEnd(source, index);
      canStartRegularExpression = expressionPrefixKeywords.has(source.slice(index, end));
      index = end;
      continue;
    }
    if (source[index] === "+" || source[index] === "-") {
      const operator = source[index]!;
      if (source[index + 1] === operator) {
        // A postfix update ends an expression; a prefix update still expects one.
        index += 2;
        continue;
      }
      canStartRegularExpression = true;
      index++;
      continue;
    }
    if ("([{:;,=!?&|*%^~<>".includes(source[index]!)) {
      canStartRegularExpression = true;
      index++;
      continue;
    }
    if (source[index] !== "." && !/\s/.test(source[index]!)) canStartRegularExpression = false;
    index++;
  }
  return source.length;
}

const expressionPrefixKeywords = new Set([
  "await", "case", "delete", "do", "else", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield",
]);

function skipRegularExpression(source: string, index: number): number {
  let inCharacterClass = false;
  for (index++; index < source.length; index++) {
    if (source[index] === "\\") {
      index++;
      continue;
    }
    if (source[index] === "[") inCharacterClass = true;
    if (source[index] === "]") inCharacterClass = false;
    if (source[index] === "/" && !inCharacterClass) {
      index++;
      while (isIdentifierPart(source[index]!)) index++;
      return index;
    }
    if (source[index] === "\n" || source[index] === "\r") break;
  }
  throw new SyntaxError("unterminated regular expression in template substitution");
}

function skipTemplateLiteral(source: string, index: number): number {
  for (index++; index < source.length; index++) {
    if (source[index] === "\\") {
      index++;
      continue;
    }
    if (source[index] === "`") return index + 1;
    if (source[index] === "$" && source[index + 1] === "{") {
      index = findTemplateSubstitutionEnd(source, index + 2);
    }
  }
  return source.length;
}

function isIdentifierStart(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z_$]/.test(character);
}

function isIdentifierPart(character: string | undefined): boolean {
  return character !== undefined && /[A-Za-z0-9_$]/.test(character);
}

function readIdentifierEnd(source: string, index: number): number {
  while (isIdentifierPart(source[index])) index++;
  return index;
}

function isQuote(character: string | undefined): boolean {
  return character === "'" || character === '"' || character === "`";
}

async function importDefinition(importPath: string, importCodePolicy: NonNullable<PolicyLoaderOptions["importCodePolicy"]>): Promise<unknown> {
  try {
    return await importCodePolicy(pathToFileURL(importPath).href);
  } catch (error) {
    const detail = error instanceof Error ? `code policy import failed: ${error.message}` : "code policy import failed";
    throw new PolicyStartupError(importPath, detail, error);
  }
}

function loadDefinition(path: string, module: unknown): ValidatedBashPolicy {
  if (!isRecord(module) || Object.keys(module).length !== 1 || !("default" in module)) {
    throw new PolicyStartupError(path, "code policy must export exactly one default policy definition");
  }
  const definition = module.default;
  if (!isRecord(definition) || !Object.isFrozen(definition)) {
    throw new PolicyStartupError(path, "code policy definition must be frozen");
  }
  requireExactDefinitionSchema(path, definition);
  if (definition.apiVersion !== 1) throw new PolicyStartupError(path, "code policy apiVersion must be 1");
  if (definition.layer !== "guard" && definition.layer !== "permission") {
    throw new PolicyStartupError(path, "code policy layer must be guard or permission");
  }
  if (!Array.isArray(definition.select) || !definition.select.every(isSelector) || typeof definition.evaluate !== "function") {
    throw new PolicyStartupError(path, "code policy must provide selectors and evaluate");
  }

  const select = freezeSelectors(path, definition.select as readonly BashPolicySelector[]);
  const candidate: LoadedBashPolicy = Object.freeze({
    source: Object.freeze({ canonicalPath: path }),
    layer: definition.layer,
    select,
    evaluate: (event: BashPolicyEvent) => evaluateDefinition(path, definition as CodePolicyDefinition, event),
  });
  try {
    return validateLoadedBashPolicy(candidate as ValidatedBashPolicy);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "invalid code policy definition";
    throw new PolicyStartupError(path, detail, error);
  }
}

function evaluateDefinition(path: string, definition: CodePolicyDefinition, event: BashPolicyEvent): PolicyDecision {
  try {
    const decision = definition.evaluate(event);
    if (definition.layer === "guard" && decision.kind === "allow") {
      throw new PolicyStartupError(path, "guard policy cannot return allow");
    }
    return decision;
  } catch (error) {
    if (error instanceof PolicyStartupError) throw error;
    const detail = error instanceof Error ? `policy evaluation failed: ${error.message}` : "policy evaluation failed";
    throw new PolicyStartupError(path, detail, error);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSelector(value: unknown): value is BashPolicySelector {
  return isRecord(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
    && Object.hasOwn(value, "kind")
    && typeof value.kind === "string";
}

function requireExactDefinitionSchema(path: string, definition: Record<string, unknown>): void {
  const expected = new Set(["apiVersion", "layer", "select", "evaluate"]);
  if ((Object.getPrototypeOf(definition) !== Object.prototype && Object.getPrototypeOf(definition) !== null)
    || Reflect.ownKeys(definition).length !== expected.size
    || Reflect.ownKeys(definition).some((key) => typeof key !== "string" || !expected.has(key))) {
    throw new PolicyStartupError(path, "code policy definition contains unsupported fields");
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(definition, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new PolicyStartupError(path, "code policy definition fields must be own data properties");
    }
  }
}

function freezeSelectors(path: string, selectors: readonly BashPolicySelector[]): readonly BashPolicySelector[] {
  try {
    for (const selector of selectors) deepFreeze(selector);
    return Object.freeze([...selectors]);
  } catch (error) {
    const detail = error instanceof Error ? `cannot freeze policy selectors: ${error.message}` : "cannot freeze policy selectors";
    throw new PolicyStartupError(path, detail, error);
  }
}

function deepFreeze(value: unknown, seen: WeakSet<object> = new WeakSet()): void {
  if (value === null || typeof value !== "object") {
    if (typeof value === "function") throw new TypeError("selector data must not contain functions");
    return;
  }
  if (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new TypeError("selector data must contain only primitives, arrays, and plain objects");
  }
  if (seen.has(value)) return;
  seen.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && "value" in descriptor) deepFreeze(descriptor.value, seen);
    else if (descriptor !== undefined) throw new TypeError("selector data cannot contain accessor properties");
  }
  Object.freeze(value);
}
