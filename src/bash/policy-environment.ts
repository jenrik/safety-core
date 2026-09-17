import type { BashInitialEnvironment } from "../authorization.js";

export type PolicyEnvironmentDisposition = "defer" | "trusted" | "ignored" | "excluded-secret";

export interface PolicyEnvironmentRoute {
  readonly name: string;
  readonly disposition: PolicyEnvironmentDisposition;
  readonly scope: "gh" | "git" | "shared";
  readonly rationale: string;
  readonly capture: boolean;
}

/** Internal fact used so gh can inspect inherited PAGER without changing Git's accepted ambient pager boundary. */
export const GH_INHERITED_PAGER_FACT = "__SAFETY_CORE_INHERITED_GH_PAGER";
const PRESENT_REDACTED_VALUE = "__SAFETY_CORE_PRESENT";

export const POLICY_ENVIRONMENT_ROUTES: readonly PolicyEnvironmentRoute[] = Object.freeze([
  excludedSecret("GH_TOKEN"),
  excludedSecret("GITHUB_TOKEN"),
  excludedSecret("GH_ENTERPRISE_TOKEN"),
  excludedSecret("GITHUB_ENTERPRISE_TOKEN"),
  ghDefer("GH_CONFIG_DIR", "Redirects configuration and dynamic alias discovery."),
  ghDefer("GH_HOST", "Redirects authentication and requests to another host."),
  ghDefer("GH_REPO", "Changes repository selection without an audited command argument."),
  ghDefer("GH_EDITOR", "Can execute an arbitrary editor."),
  ghDefer("GIT_EDITOR", "Can execute an arbitrary editor used by gh."),
  ghDefer("VISUAL", "Can execute an arbitrary editor used by gh."),
  ghDefer("EDITOR", "Can execute an arbitrary editor used by gh."),
  ghDefer("GH_BROWSER", "Can execute an arbitrary browser command."),
  ghDefer("BROWSER", "Can execute an arbitrary browser command."),
  ghDefer("GH_DEBUG", "Can emit request, response, and authentication diagnostics."),
  ghDefer("DEBUG", "Can emit verbose diagnostics."),
  ghDefer("GH_PAGER", "Can execute an arbitrary pager command."),
  Object.freeze({ name: "PAGER", disposition: "defer", scope: "gh", rationale: "Can execute an arbitrary gh pager command; ambient Git paging remains trusted.", capture: true }),
  ghDefer("GLAMOUR_STYLE", "Redirects Markdown rendering through an unreviewed style or path."),
  ignored("NO_COLOR", "Disables color and terminal escape sequences."),
  ignored("CLICOLOR", "Only changes color rendering."),
  ghDefer("CLICOLOR_FORCE", "Can force terminal escape sequences in non-terminal output."),
  ghDefer("GH_COLOR_LABELS", "Changes terminal rendering to emit true-color sequences."),
  ghDefer("GH_ACCESSIBLE_COLORS", "Enables preview terminal rendering behavior."),
  ghDefer("GH_FORCE_TTY", "Forces terminal rendering and can enable prompts or pagers."),
  trusted("GH_NO_UPDATE_NOTIFIER", "Disables update checks and notices."),
  trusted("GH_NO_EXTENSION_UPDATE_NOTIFIER", "Disables extension update checks and notices."),
  ghDefer("GH_EXTENSION", "Changes extension execution behavior."),
  trusted("GH_PROMPT_DISABLED", "Any present value disables prompts and prevents configured editor prompting."),
  ghDefer("GH_PATH", "Redirects gh executable discovery."),
  ghDefer("GH_MDWIDTH", "Changes Markdown rendering behavior."),
  ghDefer("GH_ACCESSIBLE_PROMPTER", "Enables preview prompt behavior."),
  ghDefer("GH_TELEMETRY", "Can emit telemetry diagnostics or alter network telemetry behavior."),
  ghDefer("GH_TELEMETRY_SAMPLE_RATE", "Changes whether telemetry launches the gh executable as an external sender."),
  trusted("DO_NOT_TRACK", "Disables telemetry."),
  trusted("GH_SPINNER_DISABLED", "Disables animated spinner output."),
  ignored("XDG_CONFIG_HOME", "Default configuration lookup is accepted only by static local allow rules."),
  ignored("AppData", "Windows default configuration lookup is accepted only by static local allow rules."),
  ignored("HOME", "Default configuration lookup is accepted only by static local allow rules."),
  gitDefer("GIT_CONFIG_COUNT", "Injects Git configuration."),
  gitDefer("GIT_CONFIG_GLOBAL", "Redirects global Git configuration."),
  gitDefer("GIT_CONFIG_PARAMETERS", "Injects Git configuration."),
  gitDefer("GIT_CONFIG_SYSTEM", "Redirects system Git configuration."),
  gitDefer("GIT_EXTERNAL_DIFF", "Executes an external diff helper."),
  gitDefer("GIT_PAGER", "Executes an explicit Git pager command."),
  sharedDefer("BASH_ENV", "Loads and executes a Bash startup file."),
  sharedDefer("ENV", "Loads and executes a POSIX or Korn shell startup file."),
  sharedDefer("ZDOTDIR", "Redirects zsh startup-file discovery."),
]);

export const GH_DEFER_ENVIRONMENT_NAMES: readonly string[] = Object.freeze([
  ...POLICY_ENVIRONMENT_ROUTES.filter((route) => route.scope === "gh" && route.disposition === "defer").map((route) => route.name),
  GH_INHERITED_PAGER_FACT,
]);

/** Variables consulted by common gh startup or by both owned network routes. */
export const GH_GLOBAL_DEFER_ENVIRONMENT_NAMES: readonly string[] = Object.freeze([
  "GH_CONFIG_DIR",
  "GH_HOST",
  "GH_DEBUG",
  "DEBUG",
  "CLICOLOR_FORCE",
  "GH_COLOR_LABELS",
  "GH_ACCESSIBLE_COLORS",
  "GH_FORCE_TTY",
  "GH_PATH",
  "GH_TELEMETRY",
  "GH_TELEMETRY_SAMPLE_RATE",
]);

export const GH_API_DEFER_ENVIRONMENT_NAMES: readonly string[] = Object.freeze([
  ...GH_GLOBAL_DEFER_ENVIRONMENT_NAMES,
  "GH_REPO",
]);

/**
 * Capture only reviewed behavior facts. Authentication tokens and all unknown
 * process variables are omitted, credential-capable configuration payloads are
 * reduced to presence facts, and callers never serialize captured values.
 */
export function policyInitialEnvironment(environment: Readonly<Record<string, string | undefined>>): BashInitialEnvironment {
  const captured = new Set(POLICY_ENVIRONMENT_ROUTES.filter((route) => route.capture).map((route) => route.name));
  const values: Record<string, string> = {};
  for (const [name, value] of Object.entries(environment)) {
    if (value === undefined) continue;
    if (name === "PAGER") {
      values[GH_INHERITED_PAGER_FACT] = value;
      continue;
    }
    if (name === "GIT_CONFIG_PARAMETERS") {
      values[name] = value.length === 0 ? "" : PRESENT_REDACTED_VALUE;
      continue;
    }
    if (captured.has(name) || /^GIT_CONFIG_KEY_\d+$/.test(name)) values[name] = value;
  }
  const unset = [...captured].filter((name) => environment[name] === undefined);
  return Object.freeze({ kind: "filtered", values: Object.freeze(values), unset: Object.freeze(unset) });
}

function excludedSecret(name: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "excluded-secret", scope: "gh", rationale: "Authentication values must never enter policy analysis.", capture: false });
}

function ghDefer(name: string, rationale: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "defer", scope: "gh", rationale, capture: true });
}

function gitDefer(name: string, rationale: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "defer", scope: "git", rationale, capture: true });
}

function sharedDefer(name: string, rationale: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "defer", scope: "shared", rationale, capture: true });
}

function trusted(name: string, rationale: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "trusted", scope: "gh", rationale, capture: true });
}

function ignored(name: string, rationale: string): PolicyEnvironmentRoute {
  return Object.freeze({ name, disposition: "ignored", scope: "gh", rationale, capture: false });
}
