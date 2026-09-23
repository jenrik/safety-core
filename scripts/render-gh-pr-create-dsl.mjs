/** Render a complete JSON DCRM source with fixed, normalized PR allowlists. */
export function renderGhPrCreateDslPolicy(options) {
  const allowedRepositories = normalize(options.allowedRepositories, "allowedRepositories", 2, 3);
  const allowedOrganizations = normalize(options.allowedOrganizations, "allowedOrganizations", 1, 2);
  const call = (name, ...args) => ({ call: name, args });
  const word = (value) => call("equals", { ref: "word" }, value);
  const defer = { decision: "defer", audit: { invocation: { ref: "event" } } };
  const deny = (reason) => ({ decision: "deny", reason: [reason], audit: { invocation: { ref: "event" } } });
  const repository = call("parseRepository", { ref: "repository" });
  const repoAllowed = { any: [
    ...allowedRepositories.map((value) => {
      const [host, owner, name] = value.split("/");
      return call("repositoryMatches", repository, host ?? "github.com", owner, name ?? owner);
    }),
    ...allowedOrganizations.map((value) => {
      const [host, owner] = value.includes("/") ? value.split("/") : ["github.com", value];
      return call("repositoryMatchesOrganization", repository, host, owner);
    }),
  ] };
  const routeSafe = { all: [
    call("isDirectExecutable", "gh"), call("assignmentsAreSubset", ["GH_PROMPT_DISABLED"]),
    { not: call("hasRedirect") }, { not: call("hasInheritedExecutableFunction", "gh") },
    { not: { any: [
      call("hasProvenanceRoute", "eval"),
      call("hasProvenanceRoute", "shell-command"),
      call("hasProvenanceRoute", "binding-derived-script"),
    ] } },
    { not: call("environmentAnyUnsafe", ["GH_CONFIG_DIR", "GH_HOST", "GH_DEBUG", "DEBUG", "CLICOLOR_FORCE", "GH_COLOR_LABELS", "GH_ACCESSIBLE_COLORS", "GH_FORCE_TTY", "GH_PATH", "GH_TELEMETRY", "GH_TELEMETRY_SAMPLE_RATE"]) },
    call("environmentIsExported", "GH_PROMPT_DISABLED"),
  ] };
  return `${JSON.stringify({
    language: "safety-core/bash-policy-v1", layer: "permission",
    select: [{ executable: { projection: "basename", equals: "gh" } }],
    registers: {
      repository: { type: "inputRef", initial: null }, hasRepository: { type: "bool", initial: false },
      title: { type: "bool", initial: false }, body: { type: "bool", initial: false }, fill: { type: "bool", initial: false },
      draft: { type: "bool", initial: false }, base: { type: "bool", initial: false }, head: { type: "bool", initial: false },
      milestone: { type: "bool", initial: false }, noMaintainerEdit: { type: "bool", initial: false }, unsafe: { type: "bool", initial: false },
    }, folds: {},
    options: {
      repo: { names: ["--repo", "-R"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { repository: { ref: "option.value" }, hasRepository: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "hasRepository" }] } } },
      title: { names: ["--title", "-t"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { title: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "title" }] } } },
      body: { names: ["--body", "-b"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { body: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "body" }] } } },
      fill: { names: ["--fill", "-f", "--fill-first", "--fill-verbose"], value: "absent", forms: [], availableIn: "*", set: { fill: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "fill" }] } } },
      base: { names: ["--base", "-B"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { base: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "base" }] } } },
      head: { names: ["--head", "-H"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { head: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "head" }] } } },
      milestone: { names: ["--milestone", "-m"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { milestone: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "milestone" }] } } },
      safeRepeatableValue: { names: ["--reviewer", "-r", "--assignee", "-a", "--label", "-l", "--project", "-p"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: {} },
      draft: { names: ["--draft", "-d"], value: "absent", forms: [], availableIn: "*", set: { draft: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "draft" }] } } },
      noMaintainerEdit: { names: ["--no-maintainer-edit"], value: "absent", forms: [], availableIn: "*", set: { noMaintainerEdit: true, unsafe: { any: [{ ref: "unsafe" }, { ref: "noMaintainerEdit" }] } } },
      unsafeValue: { names: ["--body-file", "-F", "--recover", "--template", "-T", "--attach"], value: "required", forms: ["separate", "attachedShort", "equalsLong", "cluster"], availableIn: "*", set: { unsafe: true } },
      unsafeBoolean: { names: ["--editor", "-e", "--web", "-w", "--dry-run"], value: "absent", forms: [], availableIn: "*", set: { unsafe: true } },
    }, fragments: {}, start: "start",
    states: {
      start: { cases: [{ when: word("pr"), action: { consume: "word", next: "pr" } }, { when: word("api"), action: { decision: "ignore" } }, { when: true, action: { decision: "ignore" } }], default: { decision: "ignore" }, end: { decision: "ignore" } },
      pr: { cases: [{ when: { any: [word("create"), word("new")] }, action: { consume: "word", next: "create" } }, { when: true, action: { decision: "ignore" } }], default: { decision: "ignore" }, end: { decision: "ignore" } },
      create: { cases: [
        { when: true, action: { consume: "word", next: "invalid" } },
        { when: { ref: "unsafe" }, action: deny("Pull-request creation is blocked: malformed or interactive gh pr create arguments require native permission") },
        { when: { not: routeSafe }, action: deny("Pull-request creation is blocked through an explicit executable path, leading environment assignment, redirection, or unsafe GitHub environment") },
        { when: { not: { ref: "hasRepository" } }, action: deny("Pull-request creation is blocked: provide an explicit --repo HOST/OWNER/REPO target that is allowlisted by the ghPrCreate profile") },
        { when: { not: call("repositoryHasExplicitHost", repository) }, action: deny("Pull-request creation is blocked: use an explicit --repo HOST/OWNER/REPO target so the allowlist cannot be redirected by GH_HOST") },
        { when: { not: repoAllowed }, action: deny("Pull-request creation is blocked: the requested repository is not allowlisted by the ghPrCreate profile") },
        { when: { all: [{ not: { ref: "fill" } }, { not: { all: [{ ref: "title" }, { ref: "body" }] } }] }, action: deny("Pull-request creation is blocked: provide --fill or both --title and --body") },
        { when: true, action: { decision: "allow", reason: ["gh pr create auto-allowed for an allowlisted repository"], audit: { invocation: { ref: "event" } } } },
      ], default: deny("Pull-request creation is blocked: malformed or interactive gh pr create arguments require native permission"), end: defer },
      invalid: { cases: [], default: deny("Pull-request creation is blocked: malformed or interactive gh pr create arguments require native permission"), end: deny("Pull-request creation is blocked: malformed or interactive gh pr create arguments require native permission") },
    },
  }, null, 2)}\n`;
}

function normalize(values, name, min, max) {
  if (!Array.isArray(values)) throw new TypeError(`${name} must be an array of repository identifiers`);
  const normalized = values.map((value, index) => {
    if (typeof value !== "string") throw new TypeError(`${name}[${index}] must be a string`);
    const parts = value.trim().toLowerCase().split("/");
    if (parts.length < min || parts.length > max || !parts.every((part) => /^[a-z0-9][a-z0-9._-]*$/.test(part))) throw new TypeError(`${name}[${index}] must be a slash-separated GitHub identifier`);
    return parts.join("/");
  });
  if (new Set(normalized).size !== normalized.length) throw new TypeError(`${name} must not contain duplicate identifiers`);
  return normalized.sort();
}

if (process.argv[1] === new URL(import.meta.url).pathname) process.stdout.write(renderGhPrCreateDslPolicy(JSON.parse(process.argv[2] ?? "{}")));
