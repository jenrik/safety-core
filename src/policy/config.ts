import { createHash } from "node:crypto";
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

export interface PiAdapterConfig {
  /** Automatically accept policy-deferred Bash calls in the Pi adapter. */
  readonly autoApprove: boolean;
  /** Optional Pi provider/model key used for the secret-command judge. */
  readonly judgeModel?: string;
}

export interface GlobalPolicyConfig {
  readonly path: string;
  readonly configuration: PolicyConfigurationSource;
  readonly version: 1;
  readonly policies: readonly string[];
  readonly projectPolicies: ProjectPoliciesConfig;
  readonly bashAnalysis: BashAnalysisConfig;
  readonly pi: PiAdapterConfig;
}

export interface ResolvedPolicySource {
  readonly path: string;
  readonly scope: "global" | "project";
}

/** Immutable identity of configuration bytes selected at session startup. */
export interface PolicyConfigurationSource {
  readonly canonicalPath: string;
  readonly scope: "global" | "project";
  readonly sha256: string;
}

export interface ResolvedSessionPolicyConfig {
  readonly global: GlobalPolicyConfig;
  readonly projectRoot?: string;
  readonly configurations: readonly PolicyConfigurationSource[];
  readonly sources: readonly ResolvedPolicySource[];
}

type Environment = Readonly<Record<string, string | undefined>>;

/** Load the authoritative global file selected solely by environment presence. */
export function loadGlobalPolicyConfig(env: Environment = process.env): GlobalPolicyConfig {
  const path = canonicalPath(globalConfigPath(env), "global configuration");
  const document = readJson(path);
  return parseGlobalConfig(document.value, path, configurationSource(path, "global", document.bytes));
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
  const configurations = project === undefined ? [config.configuration] : [config.configuration, project.configuration];

  return Object.freeze({
    global: config,
    ...(project === undefined ? {} : { projectRoot: project.root }),
    configurations: Object.freeze(configurations),
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

function readJson(path: string): { readonly bytes: Buffer; readonly value: unknown } {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    throw new PolicyStartupError(path, "cannot read configuration", error);
  }
  try {
    return Object.freeze({ bytes, value: JSON.parse(bytes.toString("utf8")) });
  } catch (error) {
    throw new PolicyStartupError(path, "malformed JSON configuration", error);
  }
}

function parseGlobalConfig(value: unknown, path: string, configuration: PolicyConfigurationSource): GlobalPolicyConfig {
  const record = requireRecord(value, path, "configuration must be an object");
  requireOnlyKeys(record, new Set(["version", "policies", "projectPolicies", "bashAnalysis", "pi"]), path);
  if (record.version !== 1) throw new PolicyStartupError(path, "version must be 1");
  const policies = parsePolicies(record.policies, path);
  requireGlobalSourceExtensions(policies, path);
  const projectPolicies = parseProjectPolicies(record.projectPolicies, path);
  const bashAnalysis = parseBashAnalysis(record.bashAnalysis, path);
  const pi = parsePiAdapter(record.pi, path);

  return Object.freeze({
    path,
    configuration,
    version: 1,
    policies: Object.freeze(policies),
    projectPolicies,
    bashAnalysis,
    pi,
  });
}

function parsePiAdapter(value: unknown, path: string): PiAdapterConfig {
  if (value === undefined) return Object.freeze({ autoApprove: false });
  const record = requireRecord(value, path, "pi must be an object");
  requireOnlyKeys(record, new Set(["autoApprove", "judgeModel"]), path);
  const autoApprove = record.autoApprove ?? false;
  if (typeof autoApprove !== "boolean") throw new PolicyStartupError(path, "pi.autoApprove must be a boolean");
  const judgeModel = record.judgeModel;
  if (judgeModel !== undefined && (typeof judgeModel !== "string" || judgeModel.length === 0)) {
    throw new PolicyStartupError(path, "pi.judgeModel must be a non-empty string");
  }
  return Object.freeze({ autoApprove, ...(judgeModel === undefined ? {} : { judgeModel }) });
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
): { readonly root: string; readonly configuration: PolicyConfigurationSource; readonly sources: readonly ResolvedPolicySource[] } | undefined {
  if (config.projectPolicies.mode === "disabled") return undefined;
  const root = findNearestProjectRoot(canonicalCwd);
  if (root === undefined) return undefined;
  if (config.projectPolicies.mode === "allowlisted") {
    if (!allowedRoots.includes(root)) return undefined;
  }

  const configPath = canonicalPath(join(root, ".safety-core", "config.json"), "project configuration");
  const document = readJson(configPath);
  const record = requireRecord(document.value, configPath, "project configuration must be an object");
  requireOnlyKeys(record, new Set(["version", "policies"]), configPath);
  if (record.version !== 1) throw new PolicyStartupError(configPath, "version must be 1");
  const policies = parsePolicies(record.policies, configPath);
  requireSourceExtensions(policies, ".policy.json", "project", configPath);
  const sources = policies
    .map((reference) => resolveSource(reference, root, "project", configPath));
  return Object.freeze({
    root,
    configuration: configurationSource(configPath, "project", document.bytes),
    sources: Object.freeze(sources),
  });
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
  const valid = scope === "global" ? path.endsWith(".policy.mjs") || path.endsWith(".policy.json") : path.endsWith(".policy.json");
  if (!valid) {
    const extensions = scope === "global" ? ".policy.mjs or .policy.json" : ".policy.json";
    throw new PolicyStartupError(configPath, `${scope} policy source must use the exact ${extensions} extension: ${reference}`);
  }
  return Object.freeze({ path, scope });
}

function requireGlobalSourceExtensions(references: readonly string[], path: string): void {
  const invalid = references.find((reference) => !reference.endsWith(".policy.mjs") && !reference.endsWith(".policy.json"));
  if (invalid !== undefined) throw new PolicyStartupError(path, `global policy source must use .policy.mjs or .policy.json: ${invalid}`);
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

function configurationSource(canonicalPath: string, scope: PolicyConfigurationSource["scope"], bytes: Buffer): PolicyConfigurationSource {
  return Object.freeze({
    canonicalPath,
    scope,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}
