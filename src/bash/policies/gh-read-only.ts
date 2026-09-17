export type GhDisposition = "allow" | "defer" | "owned";
export type GhExclusionReason =
  | "arbitrary-content"
  | "external-execution"
  | "interaction"
  | "local-input"
  | "local-output"
  | "mutation"
  | "unreviewed-behavior";

export interface GhOperandGrammar {
  readonly minimum: number;
  readonly maximum: number;
  readonly values?: readonly string[];
}

export interface GhFlagGrammar {
  readonly long?: string;
  readonly short?: string;
  readonly takesValue: boolean;
  readonly required?: boolean;
  readonly repeatable?: boolean;
  readonly values?: readonly string[];
  readonly forms: readonly ("separate" | "equals" | "attached")[];
}

export interface GhCommandRule {
  readonly path: readonly string[];
  readonly aliases: readonly (readonly string[])[];
  readonly kind: "command" | "group" | "top-level-command" | "hidden-command";
  readonly preview: boolean;
  readonly disposition: GhDisposition;
  readonly owner?: "ghApiReadOnly" | "ghPrCreate";
  readonly operands: GhOperandGrammar;
  readonly flags: readonly GhFlagGrammar[];
  readonly outputTrust: string;
  readonly environmentRoutes: readonly string[];
  readonly evidence: string;
  readonly rationale: string;
  readonly exclusionReason?: GhExclusionReason;
}

export const GH_CLI_AUDIT_VERSION = "2.100.0";
export const GH_CLI_AUDIT_COMMIT = "45437bc7eeeb3359bbfddd1742f79de7652fd3e2";

const COMMAND_PATHS = lines(`
accessibility
actions
agent-task
agent-task create
agent-task list
agent-task view
alias
alias delete
alias import
alias list
alias set
api
attestation
attestation download
attestation inspect
attestation trusted-root
attestation verify
auth
auth git-credential
auth login
auth logout
auth refresh
auth setup-git
auth status
auth switch
auth token
browse
cache
cache delete
cache list
codespace
codespace code
codespace cp
codespace create
codespace delete
codespace edit
codespace jupyter
codespace list
codespace logs
codespace ports
codespace ports forward
codespace ports visibility
codespace rebuild
codespace select
codespace ssh
codespace stop
codespace view
completion
config
config clear-cache
config get
config list
config set
copilot
credits
discussion
discussion comment
discussion create
discussion edit
discussion list
discussion view
extension
extension browse
extension create
extension exec
extension install
extension list
extension remove
extension search
extension upgrade
gist
gist clone
gist create
gist delete
gist edit
gist list
gist rename
gist view
gpg-key
gpg-key add
gpg-key delete
gpg-key list
issue
issue close
issue comment
issue create
issue delete
issue develop
issue edit
issue list
issue lock
issue pin
issue reopen
issue status
issue transfer
issue unlock
issue unpin
issue view
label
label clone
label create
label delete
label edit
label list
licenses
org
org list
pr
pr checkout
pr checks
pr close
pr comment
pr create
pr diff
pr edit
preview
preview prompter
pr list
pr lock
pr merge
project
project close
project copy
project create
project delete
project edit
project field-create
project field-delete
project field-list
project item-add
project item-archive
project item-create
project item-delete
project item-edit
project item-list
project link
project list
project mark-template
project unlink
project view
pr ready
pr reopen
pr revert
pr review
pr status
pr unlock
pr update-branch
pr view
release
release create
release delete
release delete-asset
release download
release edit
release list
release upload
release verify
release verify-asset
release view
repo
repo archive
repo autolink
repo autolink create
repo autolink delete
repo autolink list
repo autolink view
repo clone
repo create
repo credits
repo delete
repo deploy-key
repo deploy-key add
repo deploy-key delete
repo deploy-key list
repo edit
repo fork
repo garden
repo gitignore
repo gitignore list
repo gitignore view
repo license
repo license list
repo license view
repo list
repo read-dir
repo read-file
repo rename
repo set-default
repo sync
repo unarchive
repo view
ruleset
ruleset check
ruleset list
ruleset view
run
run cancel
run delete
run download
run list
run rerun
run view
run watch
search
search code
search commits
search issues
search prs
search repos
secret
secret delete
secret list
secret set
send-telemetry
skill
skill install
skill list
skill preview
skill publish
skill search
skill update
ssh-key
ssh-key add
ssh-key delete
ssh-key list
status
variable
variable delete
variable get
variable list
variable set
version
workflow
workflow disable
workflow enable
workflow list
workflow run
workflow view
`);

const GROUP_PATHS = new Set(lines(`
agent-task
alias
attestation
auth
cache
codespace
codespace ports
config
discussion
extension
gist
gpg-key
issue
label
org
pr
preview
project
release
repo
repo autolink
repo deploy-key
repo gitignore
repo license
ruleset
run
search
secret
skill
ssh-key
variable
workflow
`));

const TOP_LEVEL_COMMANDS = new Set(lines(`
api
browse
completion
copilot
licenses
status
`));

const HIDDEN_COMMANDS = new Set(lines(`
accessibility
actions
attestation inspect
auth git-credential
codespace select
credits
repo credits
repo garden
send-telemetry
version
`));

const PREVIEW_COMMANDS = new Set(lines(`
agent-task
agent-task create
agent-task list
agent-task view
copilot
discussion
discussion comment
discussion create
discussion edit
discussion list
discussion view
repo read-dir
repo read-file
skill
skill install
skill list
skill preview
skill publish
skill search
skill update
`));

const NATIVE_ALIASES: Readonly<Record<string, readonly string[]>> = Object.freeze({
  accessibility: ["a11y"],
  "agent-task": ["agent-tasks", "agent", "agents"],
  "alias list": ["alias ls"],
  attestation: ["at"],
  "cache list": ["cache ls"],
  codespace: ["cs"],
  "codespace list": ["codespace ls", "cs ls"],
  "config list": ["config ls"],
  "discussion list": ["discussion ls"],
  extension: ["extensions", "ext"],
  "extension list": ["ext ls", "extension ls", "extensions ls"],
  "extension remove": ["ext uninstall", "extension uninstall", "extensions uninstall"],
  "gist create": ["gist new"],
  "gist list": ["gist ls"],
  "gpg-key list": ["gpg-key ls"],
  "issue create": ["issue new"],
  "issue list": ["issue ls"],
  "label list": ["label ls"],
  "org list": ["org ls"],
  "pr checkout": ["pr co"],
  "pr create": ["pr new"],
  "pr list": ["pr ls"],
  "project list": ["project ls"],
  "release create": ["release new"],
  "release list": ["release ls"],
  "repo autolink create": ["repo autolink new"],
  "repo autolink list": ["repo autolink ls"],
  "repo create": ["repo new"],
  "repo deploy-key list": ["repo deploy-key ls"],
  "repo gitignore list": ["repo gitignore ls"],
  "repo license list": ["repo license ls"],
  "repo list": ["repo ls"],
  ruleset: ["rs"],
  "ruleset list": ["rs ls", "ruleset ls"],
  "run list": ["run ls"],
  "secret delete": ["secret remove"],
  "secret list": ["secret ls"],
  skill: ["skills"],
  "skill install": ["skill add", "skills add"],
  "skill list": ["skill ls", "skills ls"],
  "skill preview": ["skill show", "skills show"],
  "ssh-key list": ["ssh-key ls"],
  "variable delete": ["variable remove"],
  "variable list": ["variable ls"],
  "workflow list": ["workflow ls"],
});

const ALLOWED_PATHS = new Set<string>();
const OWNED_PATHS = new Map<string, GhCommandRule["owner"]>([
  ["api", "ghApiReadOnly"],
  ["pr create", "ghPrCreate"],
]);

const PR_CREATE_FLAGS: readonly GhFlagGrammar[] = Object.freeze([
  valueFlag("--repo", "-R"),
  booleanFlag("--draft", "-d"),
  valueFlag("--title", "-t"),
  valueFlag("--body", "-b"),
  valueFlag("--body-file", "-F"),
  valueFlag("--base", "-B"),
  valueFlag("--head", "-H"),
  booleanFlag("--editor", "-e"),
  booleanFlag("--web", "-w"),
  booleanFlag("--fill", "-f"),
  booleanFlag("--fill-first"),
  booleanFlag("--fill-verbose"),
  valueFlag("--reviewer", "-r", true),
  valueFlag("--assignee", "-a", true),
  valueFlag("--label", "-l", true),
  valueFlag("--project", "-p", true),
  valueFlag("--milestone", "-m"),
  booleanFlag("--no-maintainer-edit"),
  valueFlag("--recover"),
  valueFlag("--template", "-T"),
  booleanFlag("--dry-run"),
  valueFlag("--attach", undefined, true),
]);

const MUTATING_VERBS = new Set([
  "add", "archive", "cancel", "clear-cache", "clone", "close", "comment", "copy", "cp", "create", "delete",
  "develop", "disable", "edit", "enable", "fork", "forward", "import", "install", "link", "lock", "login",
  "logout", "mark-template", "merge", "pin", "publish", "ready", "rebuild", "refresh", "remove", "rename",
  "reopen", "rerun", "review", "revert", "run", "set", "setup-git", "stop", "switch", "sync", "transfer",
  "unarchive", "unlink", "unlock", "unpin", "update", "update-branch", "upgrade", "upload", "visibility",
]);
const LOCAL_OR_EXTERNAL_PATHS = new Set([
  "attestation download", "attestation trusted-root", "attestation verify", "browse", "codespace code", "codespace jupyter",
  "codespace ssh", "completion", "copilot", "extension browse", "extension exec", "gist clone", "preview prompter",
  "licenses", "release download", "release verify-asset", "repo clone", "repo deploy-key add", "repo read-file", "run download",
  "run watch", "skill install", "skill list", "skill preview", "skill publish", "skill update", "ssh-key add",
]);
const CREDENTIAL_PATHS = new Set([
  "alias list", "auth", "auth git-credential", "auth status", "auth token", "config", "config get", "config list",
  "extension list", "gpg-key list", "repo deploy-key list", "secret", "secret list", "ssh-key list", "variable get",
  "variable list",
]);

export const GH_READ_ONLY_RULES: readonly GhCommandRule[] = Object.freeze(COMMAND_PATHS
  .map((path) => makeRule(path))
  .sort((left, right) => compareText(left.path.join("\0"), right.path.join("\0"))));
export const GH_READ_ONLY_RULE_BY_PATH: ReadonlyMap<string, GhCommandRule> = new Map(
  GH_READ_ONLY_RULES.map((rule) => [rule.path.join(" "), rule]),
);

export const GH_HELP_TOPIC_RULES = Object.freeze([
  helpTopic("environment", "defer", "Common gh startup can migrate configuration, check for updates, and launch telemetry before rendering this static topic."),
  helpTopic("exit-codes", "defer", "Common gh startup can migrate configuration, check for updates, and launch telemetry before rendering this static topic."),
  helpTopic("formatting", "defer", "Common gh startup can migrate configuration, check for updates, and launch telemetry before rendering this static topic."),
  helpTopic("mintty", "defer", "Common gh startup can migrate configuration, check for updates, and launch telemetry before rendering this static topic."),
  helpTopic("reference", "defer", "The generated reference incorporates configured aliases and installed extensions."),
  helpTopic("telemetry", "defer", "Common gh startup can migrate configuration, check for updates, and launch telemetry before rendering this static topic."),
]);

export const GH_HELP_TOPIC_RULE_BY_NAME: ReadonlyMap<string, (typeof GH_HELP_TOPIC_RULES)[number]> = new Map(
  GH_HELP_TOPIC_RULES.map((rule) => [rule.name, rule]),
);

function makeRule(path: string): GhCommandRule {
  const owner = OWNED_PATHS.get(path);
  const allowed = ALLOWED_PATHS.has(path);
  const disposition: GhDisposition = owner ? "owned" : allowed ? "allow" : "defer";
  const assessment = disposition === "defer" ? exclusion(path) : undefined;
  return Object.freeze({
    path: Object.freeze(path.split(" ")),
    aliases: Object.freeze((NATIVE_ALIASES[path] ?? []).map((alias) => Object.freeze(alias.split(" ")))),
    kind: HIDDEN_COMMANDS.has(path) ? "hidden-command"
      : GROUP_PATHS.has(path) ? "group"
      : TOP_LEVEL_COMMANDS.has(path) ? "top-level-command"
      : "command",
    preview: PREVIEW_COMMANDS.has(path),
    disposition,
    ...(owner ? { owner } : {}),
    operands: Object.freeze({ minimum: 0, maximum: 0 }),
    flags: path === "pr create" ? PR_CREATE_FLAGS : Object.freeze([]),
    outputTrust: allowed
      ? "No command currently satisfies the startup-side-effect boundary."
      : owner
        ? `Output is assessed by ${owner}, not ghReadOnly.`
        : assessment!.outputTrust,
    environmentRoutes: Object.freeze(path === "api"
      ? ["GH_CONFIG_DIR", "GH_HOST", "GH_REPO", "GH_PAGER", "GH_DEBUG", "GH_PATH", "GH_TELEMETRY", "GH_TELEMETRY_SAMPLE_RATE"]
      : allowed ? ["GH_NO_UPDATE_NOTIFIER", "NO_COLOR"] : ["GH_CONFIG_DIR", "GH_HOST", "GH_REPO"]),
    evidence: `GitHub CLI ${GH_CLI_AUDIT_VERSION} (${GH_CLI_AUDIT_COMMIT}): gh ${path}`,
    rationale: allowed
      ? "This exact form is proven credential-safe."
      : owner
        ? `This command is intentionally classified by ${owner}.`
        : assessment!.rationale,
    ...(assessment ? { exclusionReason: assessment.reason } : {}),
  });
}

function exclusion(path: string): { reason: GhExclusionReason; rationale: string; outputTrust: string } {
  const leaf = path.split(" ").at(-1)!;
  if (["accessibility", "actions", "version"].includes(path)) return {
    reason: "external-execution",
    rationale: "Even this static route runs common gh startup, which can migrate configuration, check for updates, and launch telemetry before dispatch.",
    outputTrust: "Static command output is not enough to trust the preceding configuration, network, and external-execution routes.",
  };
  if (GROUP_PATHS.has(path)) return {
    reason: "interaction",
    rationale: "A command group without a reviewed leaf may print configuration-dependent help or trigger context-dependent selection.",
    outputTrust: "Group behavior is context-dependent and not trusted.",
  };
  if (MUTATING_VERBS.has(leaf)) return {
    reason: "mutation",
    rationale: "This command can change GitHub, repository, account, workflow, project, or local state.",
    outputTrust: "Mutation output and prompts are not trusted.",
  };
  if (LOCAL_OR_EXTERNAL_PATHS.has(path)) return {
    reason: path.includes("download") || path.includes("read-file") || path.endsWith(" clone") ? "local-output" : "external-execution",
    rationale: "This command can read or write local paths, download data, or invoke an external browser, editor, pager, helper, or program.",
    outputTrust: "Local I/O and external-program output are not trusted.",
  };
  if (CREDENTIAL_PATHS.has(path)) return {
    reason: "arbitrary-content",
    rationale: "This command can display authentication, configuration, key, secret, variable, alias, or extension information.",
    outputTrust: "Credential-adjacent configuration output is not trusted.",
  };
  if (HIDDEN_COMMANDS.has(path) || PREVIEW_COMMANDS.has(path)) return {
    reason: "unreviewed-behavior",
    rationale: "This hidden or preview route is not a stable credential-safe interface and requires review after upstream changes.",
    outputTrust: "Hidden or preview behavior is not trusted.",
  };
  if (["list", "ls", "view", "status", "search", "checks", "check", "diff", "logs", "ports", "get", "code"].includes(leaf)) return {
    reason: "arbitrary-content",
    rationale: "Successful or failure output can contain unrestricted remote content and may use a configured pager or renderer.",
    outputTrust: "Remote content, server error text, and pager output are not trusted.",
  };
  return {
    reason: "unreviewed-behavior",
    rationale: "The complete success, failure, configuration, prompt, and execution behavior is not proven credential-safe.",
    outputTrust: "Unreviewed command output is not trusted.",
  };
}

function helpTopic(name: string, disposition: "allow" | "defer", rationale: string) {
  return Object.freeze({
    name,
    disposition,
    operands: Object.freeze({ minimum: 0, maximum: 0 }),
    flags: Object.freeze([]),
    rationale,
    evidence: `GitHub CLI ${GH_CLI_AUDIT_VERSION}: gh help ${name}`,
  });
}

function booleanFlag(long: string, short?: string): GhFlagGrammar {
  return Object.freeze({ long, ...(short ? { short } : {}), takesValue: false, forms: Object.freeze(["separate"] as const) });
}

function valueFlag(long: string, short?: string, repeatable = false): GhFlagGrammar {
  return Object.freeze({
    long,
    ...(short ? { short } : {}),
    takesValue: true,
    ...(repeatable ? { repeatable: true } : {}),
    forms: Object.freeze(["separate", "equals", "attached"] as const),
  });
}

function lines(value: string): readonly string[] {
  return Object.freeze(value.trim().split("\n").map((line) => line.trim()).filter(Boolean));
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
