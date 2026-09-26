import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

import { HELM_CREDENTIAL_SAFE_COMMANDS, STRICT_ALLOWED_FLAGS, STRICT_READ_ONLY_COMMANDS } from "../src/bash/policies/read-only-data.ts";

type Expression = unknown;
type State = { cases: unknown[]; default: unknown; end: unknown };

const output = resolve(import.meta.dirname, "../policies/dsl");
const terminal = (decision: string, reason?: string, extra: Record<string, unknown> = {}) => ({ decision, ...(reason ? { reason: [reason] } : {}), ...extra });
const word = (value: string) => ({ call: "equals", args: [{ ref: "word" }, value] });
const call = (name: string, ...args: Expression[]) => ({ call: name, args });
const transition = (next: string) => ({ consume: "word", next });
const allow = (name: string, tool: string) => terminal("allow", `${tool} auto-allowed by the read-only profile`, { audit: { invocation: { ref: "event" } } });
const defer = () => terminal("defer", undefined, { audit: { invocation: { ref: "event" } } });

// This is the reviewed kubectl v1.37.0 inventory. It intentionally excludes
// credential routing, output/template, profile, and cache-writing switches.
const KUBECTL_APPLY_VALUE_OPTIONS = [
  ["--filename", "-f"], ["--kustomize", "-k"], ["--cascade"], ["--field-manager"], ["--grace-period"],
  ["--prune-allowlist"], ["--request-timeout"], ["--selector", "-l"], ["--subresource"], ["--timeout"],
] as const;
const KUBECTL_APPLY_BOOLEAN_OPTIONS = [
  "--all", "--allow-missing-template-keys", "--force", "--force-conflicts", "--openapi-patch", "--overwrite",
  "--prune", "--recursive", "-R", "--server-side", "--show-managed-fields", "--wait",
] as const;
const KUBECTL_APPLY_BARE_OPTIONS = ["--validate"] as const;
const KUBECTL_GLOBAL_VALUE_OPTIONS = [["--context"], ["--namespace", "-n"]] as const;

function safe(executable: string, environment: readonly string[] = [], secret = true): Expression {
  return { all: [
    call("isDirectExecutable", executable),
    { not: call("hasAnyAssignment") },
    { not: call("hasRedirect") },
    { not: call("hasInheritedExecutableFunction", executable) },
    { not: call("environmentAnyUnsafe", environment) },
    ...(secret ? [{ not: { ref: "fold.hasSecretOperand" } }] : []),
  ] };
}

function secretFold() {
  return {
    hasSecretOperand: {
      collection: "argv",
      operation: "any",
      when: { all: [
        { not: call("startsWith", { ref: "fold.item" }, "-") },
        { not: call("anySafeGlob", call("asciiLower", call("basename", { ref: "fold.item" })), ["*.env.example", "*.env.sample", "*.env.template", "*.env.dist"]) },
        call("anySafeGlob", call("asciiLower", call("basename", { ref: "fold.item" })), ["*.env", "*.env.*", ".envrc", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "id_dsa*", "id_ecdsa*", "*.p12", "*.pfx", "*.pkcs12", ".netrc", "credentials.json", "credentials.yaml", "credentials.yml", "*-credentials.json", "*-credentials.yaml", "*-credentials.yml", "*.credentials.json", "*.credentials.yaml", "*.credentials.yml", "service-account*.json", "service_account*.json", "secrets.json", "secrets.yaml", "secrets.yml", "*-secrets.json", "*-secrets.yaml", "*-secrets.yml", "*.secrets.json", "*.secrets.yaml", "*.secrets.yml", "*.secret.json", "*.secret.yaml", "*.secret.yml", "kubeconfig"]),
      ] },
    },
  };
}

function document(select: unknown[], states: Record<string, State>, options: Record<string, unknown> = {}, folds: Record<string, unknown> = {}, registers: Record<string, unknown> = {}) {
  return { language: "safety-core/bash-policy-v1", layer: "permission", select, registers, folds, options, fragments: {}, start: "start", states };
}

function write(name: string, value: unknown) {
  mkdirSync(output, { recursive: true });
  writeFileSync(resolve(output, name), `${JSON.stringify(value, null, 2)}\n`);
}

function generic() {
  const common = (executable: string) => ({ all: [safe(executable, executable === "git" ? ["GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_SYSTEM", "GIT_EXTERNAL_DIFF", "GIT_PAGER", "PAGER"] : []), { not: { ref: "fold.unsafeGitOption" } }] });
  const guardedAllow = (tool: string) => ({ decision: "allow", reason: [`${tool} auto-allowed by the read-only profile`], audit: { invocation: { ref: "event" } }, fold: ["hasSecretOperand", "unsafeGitOption"] });
  const guardedDefer = () => ({ ...defer(), fold: ["hasSecretOperand", "unsafeGitOption"] });
  const gitCommand = ["describe", "diff", "diff-files", "diff-index", "diff-tree", "for-each-ref", "log", "ls-files", "ls-tree", "merge-base", "name-rev", "rev-list", "rev-parse", "show", "show-ref", "verify-commit", "verify-tag"];
  const start: State = {
    cases: [
      { when: call("isDirectExecutable", "sha256sum"), action: guardedAllow("sha256sum") },
      { when: { all: [call("isDirectExecutable", "tea"), word("--help")] }, action: transition("teaEnd") },
      { when: { all: [call("isDirectExecutable", "git"), word("--help")] }, action: transition("gitExactEnd") },
      { when: { all: [call("isDirectExecutable", "git"), word("--version")] }, action: transition("gitExactEnd") },
      { when: { all: [call("isDirectExecutable", "git"), word("version")] }, action: transition("gitExactEnd") },
      ...gitCommand.map((name) => ({ when: { all: [call("isDirectExecutable", "git"), word(name)] }, action: transition("gitOpen") })),
      { when: { all: [call("isDirectExecutable", "git"), word("branch")] }, action: transition("branch") },
      { when: { all: [call("isDirectExecutable", "git"), word("tag")] }, action: transition("tag") },
      { when: { all: [call("isDirectExecutable", "git"), word("worktree")] }, action: transition("worktree") },
      { when: { all: [call("isDirectExecutable", "git"), word("submodule")] }, action: transition("submodule") },
      { when: { all: [call("isDirectExecutable", "git"), word("reflog")] }, action: transition("reflog") },
      { when: { all: [call("atEndOfArguments"), common("sha256sum")] }, action: guardedAllow("sha256sum") },
    ], default: defer(), end: defer(),
  };
  const exact = (values: string[]) => ({ cases: values.map((value) => ({ when: word(value), action: transition("gitExactEnd") })), default: guardedDefer(), end: guardedAllow("git") });
  write("generic-read-only.policy.json", document([
    { executable: { projection: "basename", equals: "git" } }, { executable: { projection: "basename", equals: "sha256sum" } }, { executable: { projection: "basename", equals: "tea" } },
  ], {
    start,
    teaEnd: { cases: [], default: guardedDefer(), end: guardedAllow("tea") },
    gitOpen: {
      cases: [
        { when: true, action: transition("gitOpen") },
        { when: { all: [call("atEndOfArguments"), common("git")] }, action: guardedAllow("git") },
      ],
      default: guardedDefer(),
      end: guardedDefer(),
    },
    gitExactEnd: { cases: [], default: guardedDefer(), end: guardedAllow("git") },
    branch: exact(["--list", "-l", "--show-current"]), tag: exact(["--list", "-l"]), worktree: exact(["list"]), submodule: exact(["status"]), reflog: exact(["show"]),
  }, {}, {
    ...secretFold(),
    unsafeGitOption: { collection: "argv", operation: "any", when: call("longOptionPrefixesAny", { ref: "fold.item" }, ["--ext-diff", "--no-index", "--open-files-in-pager", "--output", "--textconv"]) },
  }));
}

function helm() {
  const guardedAllow = () => ({ decision: "allow", reason: ["helm auto-allowed by the read-only profile"], audit: { invocation: { ref: "event" } }, fold: ["hasSecretOperand"] });
  const guardedDefer = () => ({ ...defer(), fold: ["hasSecretOperand"] });
  const permitted = (values: readonly string[]) => values.map((value) => ({ when: word(value), action: transition("accepted") }));
  write("helm-read-only.policy.json", document([{ executable: { projection: "basename", equals: "helm" } }], {
    start: { cases: [{ when: word("--help"), action: transition("exact") }, { when: word("--version"), action: transition("exact") }, ...permitted(["help", "completion", "verify"]), { when: word("show"), action: transition("show") }, { when: word("inspect"), action: transition("inspect") }, { when: word("search"), action: transition("search") }, { when: word("version"), action: transition("exact") }], default: guardedDefer(), end: guardedDefer() },
    exact: { cases: [], default: guardedDefer(), end: guardedAllow() },
    accepted: { cases: [{ when: true, action: transition("accepted") }], default: guardedDefer(), end: guardedAllow() },
    show: { cases: [{ when: word("chart"), action: transition("showChart") }], default: guardedDefer(), end: guardedDefer() },
    inspect: { cases: [{ when: word("chart"), action: transition("showChart") }], default: guardedDefer(), end: guardedDefer() },
    showChart: { cases: [{ when: true, action: transition("exact") }], default: guardedDefer(), end: guardedDefer() },
    search: { cases: permitted(["hub", "repo"]), default: guardedDefer(), end: guardedDefer() },
  }, {}, secretFold()));
}

function strict() {
  for (const [executable, paths] of Object.entries(STRICT_READ_ONLY_COMMANDS)) {
    const states: Record<string, State> = {};
    const nodes = new Map<string, { children: Map<string, string>; terminal: boolean }>();
    nodes.set("root", { children: new Map(), terminal: false });
    for (const path of paths) {
      let current = "root";
      for (const part of path.split(":")) {
        const node = nodes.get(current)!;
        const next = node.children.get(part) ?? `${current}_${part.replace(/[^A-Za-z0-9]/g, "_")}`;
        node.children.set(part, next);
        if (!nodes.has(next)) nodes.set(next, { children: new Map(), terminal: false });
        current = next;
      }
      nodes.get(current)!.terminal = true;
    }
    const env = executable === "docker" ? ["DOCKER_CONFIG"] : ["kubectl", "oc"].includes(executable) ? ["KUBECONFIG"] : [];
    const guard = executable === "kubectl"
      ? { all: [safe(executable, env), { not: { ref: "kubectlApplyOnlyOptionSeen" } }] }
      : safe(executable, env);
    const kubectlDryRunGuard = { all: [
      safe(executable, env, false),
      { not: call("hasProvenanceRoute", "transparent-wrapper") },
      { not: call("hasProvenanceRoute", "eval") },
      { not: call("hasProvenanceRoute", "shell-command") },
      { not: call("hasProvenanceRoute", "binding-derived-script") },
      { ref: "kubectlDryRunSeen" },
      { ref: "kubectlDryRunValid" },
      { not: { ref: "fold.kubectlOptionsTerminated" } },
      { not: { ref: "kubectlApplyOutputSeen" } },
      { ref: "kubectlCascadeValid" },
      { any: [
        { all: [{ ref: "kubectlHasFilename" }, { ref: "kubectlFilenameValid" }, { not: { ref: "kubectlHasKustomize" } }] },
        { all: [{ ref: "kubectlHasKustomize" }, { ref: "kubectlKustomizeValid" }, { not: { ref: "kubectlHasFilename" } }, { not: { ref: "kubectlRecursive" } }] },
      ] },
    ] };
    const guardedAllow = () => ({ decision: "allow", reason: [`${executable} auto-allowed by the read-only profile`], audit: { invocation: { ref: "event" } }, fold: ["hasSecretOperand"] });
    const guardedKubectlDryRunAllow = () => ({ decision: "allow", reason: [`${executable} auto-allowed by the read-only profile`], audit: { invocation: { ref: "event" } }, fold: ["kubectlOptionsTerminated"] });
    const guardedDefer = () => ({ ...defer(), fold: ["hasSecretOperand"] });
    const protectsKubernetesResources = executable === "kubectl" || executable === "oc";
    const protectedResource = (value: Expression) => call("wordInAsciiCaseInsensitiveSet", call("normalizeKubernetesResource", call("splitComponent", call("splitComponent", value, "/", 0), ".", 0)), ["secret", "serviceaccount", "tokenrequest"]);
    for (const [name, node] of nodes) {
      const cases: unknown[] = [...node.children].map(([part, next]) => ({ when: word(part), action: transition(next) }));
      if (name === "root") {
        cases.unshift({ when: word("--help"), action: transition("exact") }, { when: word("--version"), action: transition("exact") });
        if (executable === "kubectl") cases.push(
          { when: word("apply"), action: transition("kubectlApply") },
        );
      }
      if (protectsKubernetesResources && name === "root_get") {
        cases.push(
          { when: protectedResource({ ref: "word" }), action: guardedDefer() },
          { when: { any: [word("-"), { not: call("startsWith", { ref: "word" }, "-") }] }, action: { consume: "word", next: "getRest", set: { getFirstHasSlash: call("includes", { ref: "word" }, "/") } } },
        );
        states[name] = { cases, default: guardedDefer(), end: guardedDefer() };
        continue;
      }
      if (node.terminal && name !== "root") {
        // Only operands may extend an accepted command path. Unknown options must
        // reach the defer default instead of bypassing the audited flag table.
        cases.push({ when: { any: [word("-"), { not: call("startsWith", { ref: "word" }, "-") }] }, action: transition("accepted") });
        cases.push({ when: { all: [call("atEndOfArguments"), guard] }, action: guardedAllow() });
      }
      states[name === "root" ? "start" : name] = { cases, default: guardedDefer(), end: guardedDefer() };
    }
    states.exact = { cases: [], default: guardedDefer(), end: guardedDefer() };
    states.exact.cases.push({ when: { all: [call("atEndOfArguments"), guard] }, action: guardedAllow() });
    states.accepted = { cases: [{ when: { any: [word("-"), { not: call("startsWith", { ref: "word" }, "-") }] }, action: transition("accepted") }, { when: { all: [call("atEndOfArguments"), guard] }, action: guardedAllow() }], default: guardedDefer(), end: guardedDefer() };
    if (protectsKubernetesResources) {
      states.getRest = {
        cases: [
          { when: { all: [{ ref: "getFirstHasSlash" }, protectedResource({ ref: "word" })] }, action: guardedDefer() },
          { when: { all: [{ not: { ref: "getFirstHasSlash" } }, call("includes", { ref: "word" }, "/")] }, action: guardedDefer() },
          { when: { any: [word("-"), { not: call("startsWith", { ref: "word" }, "-") }] }, action: transition("getRest") },
          { when: { all: [call("atEndOfArguments"), guard] }, action: guardedAllow() },
        ],
        default: guardedDefer(),
        end: guardedDefer(),
      };
    }
    if (executable === "kubectl") {
      states.kubectlApply = {
        cases: [
          { when: { all: [call("atEndOfArguments"), kubectlDryRunGuard] }, action: guardedKubectlDryRunAllow() },
        ],
        default: guardedDefer(),
        end: guardedDefer(),
      };
    }
    const specs = STRICT_ALLOWED_FLAGS[executable] ?? [];
    const options: Record<string, unknown> = {};
    if (executable === "kubectl") {
      const applyStates = ["start", "kubectlApply"];
      const postApplyStates = ["kubectlApply"];
      const applyOnly = { kubectlApplyOnlyOptionSeen: true };
      const valueOption = (names: readonly string[], set: Record<string, Expression> = applyOnly) => ({
        names,
        value: "required",
        forms: names.length === 2 ? ["separate", "attachedShort", "cluster", "equalsLong"] : ["separate", "equalsLong"],
        availableIn: applyStates,
        set,
      });
      options.kubectlDryRun = {
        ...valueOption(["--dry-run"], {
          ...applyOnly,
          kubectlDryRunSeen: true,
          kubectlDryRunValid: { all: [
            { not: { ref: "kubectlDryRunSeen" } },
            call("inStringSet", { ref: "option.value" }, ["client", "server"]),
          ] },
        }),
        forms: ["equalsLong"],
      };
      for (const [index, names] of KUBECTL_APPLY_VALUE_OPTIONS.entries()) {
        const name = names[0];
        const nonEmpty = { all: [
          name === "--filename" ? { ref: "kubectlFilenameValid" } : { ref: "kubectlKustomizeValid" },
          { not: call("equals", { ref: "option.value" }, "") },
        ] };
        const set = name === "--filename" ? { ...applyOnly, kubectlHasFilename: true, kubectlFilenameValid: nonEmpty }
          : name === "--kustomize" ? { ...applyOnly, kubectlHasKustomize: true, kubectlKustomizeValid: nonEmpty }
            : name === "--cascade" ? { ...applyOnly, kubectlCascadeValid: { all: [
              { ref: "kubectlCascadeValid" }, call("inStringSet", { ref: "option.value" }, ["background", "foreground", "orphan"]),
            ] } }
              : applyOnly;
        options[`kubectlApplyValue${index}`] = valueOption(names, set);
      }
      for (const [index, name] of KUBECTL_APPLY_BOOLEAN_OPTIONS.entries()) {
        options[`kubectlApplyBoolean${index}`] = {
          names: [name], value: "absent", forms: [], availableIn: postApplyStates,
          set: { ...applyOnly, ...(name === "--recursive" || name === "-R" ? { kubectlRecursive: true } : {}) },
        };
      }
      for (const [index, name] of KUBECTL_APPLY_BARE_OPTIONS.entries()) {
        options[`kubectlApplyBare${index}`] = { names: [name], value: "absent", forms: [], availableIn: postApplyStates, set: applyOnly };
      }
      for (const [index, names] of KUBECTL_GLOBAL_VALUE_OPTIONS.entries()) {
        options[`kubectlGlobalValue${index}`] = {
          names, value: "required", forms: names.length === 2 ? ["separate", "attachedShort", "cluster", "equalsLong"] : ["separate", "equalsLong"], availableIn: "*", set: {},
        };
      }
      options.kubectlOutput = {
        names: ["--output", "-o"], value: "required", forms: ["separate", "attachedShort", "cluster", "equalsLong"], availableIn: "*", set: { kubectlApplyOutputSeen: true },
      };
    }
    for (const [index, flag] of specs.entries()) {
      if (executable === "kubectl" && [flag.long, flag.short].some((name) => ["--namespace", "-n", "--context", "--output", "-o"].includes(name ?? ""))) continue;
      options[`flag${index}`] = {
      names: [flag.long, flag.short].filter(Boolean),
      value: flag.takesValue ? "required" : "absent",
      forms: flag.takesValue ? ["separate", ...(flag.short ? ["attachedShort", "cluster"] : []), ...(flag.long ? ["equalsLong"] : [])] : [],
      availableIn: "*",
      set: {},
      };
    }
    write(`strict-${executable}.policy.json`, document(
      [{ executable: { projection: "basename", equals: executable } }],
      states,
      options,
      executable === "kubectl" ? {
        ...secretFold(),
        kubectlOptionsTerminated: { collection: "argv", operation: "any", when: call("equals", { ref: "fold.item" }, "--") },
      } : secretFold(),
      executable === "kubectl" ? {
        getFirstHasSlash: { type: "bool", initial: false },
        kubectlApplyOnlyOptionSeen: { type: "bool", initial: false },
        kubectlDryRunSeen: { type: "bool", initial: false },
        kubectlDryRunValid: { type: "bool", initial: true },
        kubectlHasFilename: { type: "bool", initial: false },
        kubectlFilenameValid: { type: "bool", initial: true },
        kubectlHasKustomize: { type: "bool", initial: false },
        kubectlKustomizeValid: { type: "bool", initial: true },
        kubectlRecursive: { type: "bool", initial: false },
        kubectlCascadeValid: { type: "bool", initial: true },
        kubectlApplyOutputSeen: { type: "bool", initial: false },
      } : protectsKubernetesResources ? { getFirstHasSlash: { type: "bool", initial: false } } : {},
    ));
  }
}

generic();
helm();
strict();
