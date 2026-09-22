import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, resolve as resolvePath } from "node:path";

export class PolicyStartupError extends Error {
  readonly sourcePath: string;
  readonly cause: unknown;

  constructor(sourcePath: string, detail: string, cause?: unknown) {
    super(`${sourcePath}: ${detail}`);
    this.name = "PolicyStartupError";
    this.sourcePath = sourcePath;
    this.cause = cause;
  }
}

export interface BashAnalysisConfig {
  readonly maxFunctionDepth: number;
  readonly maxNestedScriptDepth: number;
  readonly maxSteps: number;
  readonly maxWorkItems: number;
}

export type ProjectPolicyMode = "disabled" | "allowlisted" | "all";

export interface ProjectPoliciesConfig {
  readonly mode: ProjectPolicyMode;
  readonly allowedRoots: readonly string[];
}

export interface GlobalPolicyConfig {
  readonly path: string;
  readonly version: 1;
  readonly policies: readonly string[];
  readonly projectPolicies: ProjectPoliciesConfig;
  readonly bashAnalysis: BashAnalysisConfig;
}

export interface ResolvedPolicySource {
  readonly path: string;
  readonly scope: "global" | "project";
}

export interface ResolvedSessionPolicyConfig {
  readonly global: GlobalPolicyConfig;
  readonly projectRoot?: string;
  readonly sources: readonly ResolvedPolicySource[];
}

type Environment = Readonly<Record<string, string | undefined>>;

/** Load the authoritative global file selected solely by environment presence. */
export function loadGlobalPolicyConfig(env: Environment = process.env): GlobalPolicyConfig {
  const path = globalConfigPath(env);
  return parseGlobalConfig(readJson(path), path);
}

/** Resolve global sources and the one applicable nearest project configuration. */
export function resolveSessionPolicyConfig(config: GlobalPolicyConfig, cwd: string): ResolvedSessionPolicyConfig {
  const canonicalCwd = canonicalPath(cwd, "working directory");
  const globalSources = config.policies.map((reference) => resolveSource(reference, dirname(config.path), "global", config.path));
  const allowedRoots = config.projectPolicies.mode === "allowlisted"
    ? config.projectPolicies.allowedRoots.map((path) => canonicalPath(path, "project allowlist root"))
    : [];
  const project = resolveApplicableProjectConfig(config, canonicalCwd, allowedRoots);
  const sources = project === undefined ? globalSources : [...globalSources, ...project.sources];

  return Object.freeze({
    global: config,
    ...(project === undefined ? {} : { projectRoot: project.root }),
    sources: Object.freeze(sources),
  });
}

function globalConfigPath(env: Environment): string {
  if (env.SAFETY_CORE_CONFIG_HOME !== undefined) {
    return join(requireAbsolutePath("SAFETY_CORE_CONFIG_HOME", env.SAFETY_CORE_CONFIG_HOME), "safety-core", "config.json");
  }
  if (env.XDG_CONFIG_HOME !== undefined) {
    return join(requireAbsolutePath("XDG_CONFIG_HOME", env.XDG_CONFIG_HOME), "safety-core", "config.json");
  }
  return join(requireAbsolutePath("HOME", env.HOME), ".config", "safety-core", "config.json");
}

function requireAbsolutePath(name: string, value: string | undefined): string {
  if (typeof value !== "string" || value.length === 0 || !isAbsolute(value)) {
    throw new PolicyStartupError(name, "must be a non-empty absolute path");
  }
  return value;
}

function readJson(path: string): unknown {
  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch (error) {
    throw new PolicyStartupError(path, "cannot read configuration", error);
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new PolicyStartupError(path, "malformed JSON configuration", error);
  }
}

function parseGlobalConfig(value: unknown, path: string): GlobalPolicyConfig {
  const record = requireRecord(value, path, "configuration must be an object");
  requireOnlyKeys(record, new Set(["version", "policies", "projectPolicies", "bashAnalysis"]), path);
  if (record.version !== 1) throw new PolicyStartupError(path, "version must be 1");
  const policies = parsePolicies(record.policies, path);
  requireSourceExtensions(policies, ".policy.mjs", "global", path);
  const projectPolicies = parseProjectPolicies(record.projectPolicies, path);
  const bashAnalysis = parseBashAnalysis(record.bashAnalysis, path);

  return Object.freeze({
    path,
    version: 1,
    policies: Object.freeze(policies),
    projectPolicies,
    bashAnalysis,
  });
}

function parseProjectPolicies(value: unknown, path: string): ProjectPoliciesConfig {
  const record = requireRecord(value, path, "projectPolicies must be an object");
  const mode = record.mode;
  if (mode !== "disabled" && mode !== "allowlisted" && mode !== "all") {
    throw new PolicyStartupError(path, "projectPolicies.mode must be disabled, allowlisted, or all");
  }
  const allowedKeys = mode === "allowlisted" ? new Set(["mode", "allowedRoots"]) : new Set(["mode"]);
  requireOnlyKeys(record, allowedKeys, path);
  if (mode === "allowlisted" && !Array.isArray(record.allowedRoots)) {
    throw new PolicyStartupError(path, "projectPolicies.allowedRoots must be an array for allowlisted mode");
  }
  const allowedRoots = mode === "allowlisted" ? parseAbsolutePaths(record.allowedRoots, path, "projectPolicies.allowedRoots") : [];
  return Object.freeze({ mode, allowedRoots: Object.freeze(allowedRoots) });
}

function parseBashAnalysis(value: unknown, path: string): BashAnalysisConfig {
  const record = requireRecord(value, path, "bashAnalysis must be an object");
  const keys = new Set(["maxFunctionDepth", "maxNestedScriptDepth", "maxSteps", "maxWorkItems"]);
  requireOnlyKeys(record, keys, path);
  const parsed = Object.fromEntries([...keys].map((key) => {
    const limit = record[key];
    if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit <= 0) {
      throw new PolicyStartupError(path, `bashAnalysis.${key} must be a positive safe integer`);
    }
    return [key, limit];
  })) as BashAnalysisConfig;
  return Object.freeze(parsed);
}

function resolveApplicableProjectConfig(
  config: GlobalPolicyConfig,
  canonicalCwd: string,
  allowedRoots: readonly string[],
): { readonly root: string; readonly sources: readonly ResolvedPolicySource[] } | undefined {
  if (config.projectPolicies.mode === "disabled") return undefined;
  const root = findNearestProjectRoot(canonicalCwd);
  if (root === undefined) return undefined;
  if (config.projectPolicies.mode === "allowlisted") {
    if (!allowedRoots.includes(root)) return undefined;
  }

  const configPath = join(root, ".safety-core", "config.json");
  const record = requireRecord(readJson(configPath), configPath, "project configuration must be an object");
  requireOnlyKeys(record, new Set(["version", "policies"]), configPath);
  if (record.version !== 1) throw new PolicyStartupError(configPath, "version must be 1");
  const policies = parsePolicies(record.policies, configPath);
  requireSourceExtensions(policies, ".policy.json", "project", configPath);
  const sources = policies
    .map((reference) => resolveSource(reference, root, "project", configPath));
  return Object.freeze({ root, sources: Object.freeze(sources) });
}

function findNearestProjectRoot(canonicalCwd: string): string | undefined {
  let current = canonicalCwd;
  while (true) {
    if (existsSync(join(current, ".safety-core", "config.json"))) return current;
    const parent = dirname(current);
    if (parent === current) return undefined;
    current = parent;
  }
}

function resolveSource(reference: string, base: string, scope: ResolvedPolicySource["scope"], configPath: string): ResolvedPolicySource {
  const path = isAbsolute(reference) ? reference : resolvePath(base, reference);
  const extension = scope === "global" ? ".policy.mjs" : ".policy.json";
  if (!path.endsWith(extension)) {
    throw new PolicyStartupError(configPath, `${scope} policy source must use the exact ${extension} extension: ${reference}`);
  }
  return Object.freeze({ path, scope });
}

function parsePolicies(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || !value.every((reference) => typeof reference === "string" && reference.length > 0)) {
    throw new PolicyStartupError(path, "policies must be an array of non-empty strings");
  }
  return [...value];
}

function requireSourceExtensions(references: readonly string[], extension: string, scope: string, path: string): void {
  const invalid = references.find((reference) => !reference.endsWith(extension));
  if (invalid !== undefined) {
    throw new PolicyStartupError(path, `${scope} policy source must use the exact ${extension} extension: ${invalid}`);
  }
}

function parseAbsolutePaths(value: unknown, path: string, field: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string" && item.length > 0 && isAbsolute(item))) {
    throw new PolicyStartupError(path, `${field} must be an array of non-empty absolute paths`);
  }
  return [...value];
}

function requireRecord(value: unknown, path: string, detail: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new PolicyStartupError(path, detail);
  return value as Record<string, unknown>;
}

function requireOnlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>, path: string): void {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown !== undefined) throw new PolicyStartupError(path, `unknown configuration key: ${unknown}`);
}

function canonicalPath(path: string, subject: string): string {
  try {
    return realpathSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, `cannot canonicalize ${subject}`, error);
  }
}
