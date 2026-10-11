import { expect } from "bun:test";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";

import { loadPolicySources } from "../../../src/policy/load.ts";
import { policyTestForFile } from "../../../src/policy/testing.ts";
import type { BashPolicyEvent, InvocationView, ValidatedBashPolicy } from "../../../src/policy/types.ts";

const policyTest = policyTestForFile(import.meta.url);
const profile = { config: "tea-read-only.config.json" };
const transparentWrapperProfile = {
  ...profile,
  enabledPolicies: ["../env-command.policy.json"],
};

const teaProfileRepresentatives = [
  ["actions.policy.json", "tea actions", "allow"],
  ["actions-secrets.policy.json", "tea actions secrets", "allow"],
  ["actions-secrets-list.policy.json", "tea actions secrets list", "allow"],
  ["actions-variables.policy.json", "tea actions variables", "allow"],
  ["actions-variables-list.policy.json", "tea actions variables list", "allow"],
  ["actions-runs.policy.json", "tea actions runs", "allow"],
  ["actions-runs-list.policy.json", "tea actions runs list", "allow"],
  ["actions-runs-view.policy.json", "tea actions runs view 17", "allow"],
  ["actions-runs-logs.policy.json", "tea actions runs logs 17", "allow"],
  ["actions-workflows.policy.json", "tea actions workflows", "allow"],
  ["actions-workflows-list.policy.json", "tea actions workflows list", "allow"],
  ["actions-workflows-view.policy.json", "tea actions workflows view deploy", "allow"],
  ["admin.policy.json", "tea admin", "allow"],
  ["admin-users.policy.json", "tea admin users", "allow"],
  ["admin-users-list.policy.json", "tea admin users list", "allow"],
  ["branches.policy.json", "tea branches", "allow"],
  ["branches-list.policy.json", "tea branches list", "allow"],
  ["comments-list.policy.json", "tea comments list 17", "allow"],
  ["completion.policy.json", "tea completion", "allow"],
  ["completion-bash.policy.json", "tea completion bash", "allow"],
  ["completion-zsh.policy.json", "tea completion zsh", "allow"],
  ["completion-fish.policy.json", "tea completion fish", "allow"],
  ["completion-pwsh.policy.json", "tea completion pwsh", "allow"],
  ["help.policy.json", "tea help", "allow"],
  ["issues.policy.json", "tea issues", "allow"],
  ["issues-list.policy.json", "tea issues list", "allow"],
  ["labels.policy.json", "tea labels", "allow"],
  ["labels-list.policy.json", "tea labels list", "allow"],
  ["logins.policy.json", "tea logins", "allow"],
  ["logins-list.policy.json", "tea logins list", "allow"],
  ["logins-default.policy.json", "tea logins default", "allow"],
  ["logins-helper.policy.json", "tea logins helper", "allow"],
  ["logins-helper-store.policy.json", "tea logins helper store", "allow"],
  ["logins-helper-get.policy.json", "tea logins helper get", "defer"],
  ["logins-status.policy.json", "tea logins status", "allow"],
  ["man.policy.json", "tea man", "allow"],
  ["milestones.policy.json", "tea milestones", "allow"],
  ["milestones-list.policy.json", "tea milestones list", "allow"],
  ["milestones-issues.policy.json", "tea milestones issues v1", "allow"],
  ["notifications.policy.json", "tea notifications", "allow"],
  ["notifications-ls.policy.json", "tea notifications ls", "allow"],
  ["open.policy.json", "tea open", "defer"],
  ["organizations.policy.json", "tea organizations", "allow"],
  ["organizations-list.policy.json", "tea organizations list", "allow"],
  ["pulls.policy.json", "tea pulls", "allow"],
  ["pulls-list.policy.json", "tea pulls list", "allow"],
  ["pulls-review-comments.policy.json", "tea pulls review-comments 17", "allow"],
  ["releases.policy.json", "tea releases", "allow"],
  ["releases-list.policy.json", "tea releases list", "allow"],
  ["releases-assets.policy.json", "tea releases assets", "allow"],
  ["releases-assets-list.policy.json", "tea releases assets list v1", "allow"],
  ["repos.policy.json", "tea repos", "allow"],
  ["repos-list.policy.json", "tea repos list", "allow"],
  ["repos-search.policy.json", "tea repos search project", "allow"],
  ["ssh-keys.policy.json", "tea ssh-keys", "allow"],
  ["ssh-keys-list.policy.json", "tea ssh-keys list", "allow"],
  ["times.policy.json", "tea times", "allow"],
  ["times-list.policy.json", "tea times list", "allow"],
  ["webhooks.policy.json", "tea webhooks", "allow"],
  ["webhooks-list.policy.json", "tea webhooks list", "allow"],
  ["whoami.policy.json", "tea whoami", "allow"],
  ["wiki.policy.json", "tea wiki", "allow"],
  ["wiki-list.policy.json", "tea wiki list", "allow"],
  ["wiki-view.policy.json", "tea wiki view Home", "allow"],
  ["wiki-revisions.policy.json", "tea wiki revisions Home", "allow"],
] as const;

const issueListLongOptions = [
  ["--fields", "index,title"],
  ["--state", "closed"],
  ["--kind", "all"],
  ["--keyword", "bug"],
  ["--labels", "bug,help-wanted"],
  ["--milestones", "v1,v2"],
  ["--author", "alice"],
  ["--assignee", "bob"],
  ["--mentions", "carol"],
  ["--owner", "acme"],
  ["--org", "acme"],
  ["--from", "2026-01-01"],
  ["--until", "2026-12-31"],
  ["--page", "2"],
  ["--limit", "50"],
  ["--lm", "50"],
] as const;

const issueListShortOptions = [
  ["-f", "index,title"],
  ["-K", "all"],
  ["-k", "bug"],
  ["-L", "bug,help-wanted"],
  ["-m", "v1,v2"],
  ["-A", "alice"],
  ["-a", "bob"],
  ["-M", "carol"],
  ["-F", "2026-01-01"],
  ["-u", "2026-12-31"],
  ["-p", "2"],
] as const;

function teaInvocation(
  events: readonly BashPolicyEvent[],
  executionTarget: InvocationView["executionTarget"],
): InvocationView | undefined {
  return events.find(
    (event): event is InvocationView =>
      event.kind === "invocation" &&
      event.executable?.kind === "known" &&
      event.executable.value === "tea" &&
      event.executionTarget === executionTarget,
  );
}

function knownArgv(invocation: InvocationView): readonly string[] {
  return invocation.argv.map((argument) => {
    if (argument.kind !== "known") throw new Error("expected Tea argv to remain known through transparent wrapper");
    return argument.value;
  });
}

function directDecision(
  policy: ValidatedBashPolicy,
  argv: readonly string[],
  executionTarget: "external-path" | "shell-function" = "external-path",
): string {
  return policy.evaluate({
    kind: "invocation",
    executable: { kind: "known", value: "tea" },
    executionTarget,
    executableIdentity: {
      qualification: "incomplete",
      spelling: "tea",
      basename: "tea",
      chain: [],
      failure: { kind: "not-found" },
    },
    argv: argv.map((value) => ({ kind: "known" as const, value })),
    environment: {},
    missingBindings: "unset",
    redirects: [],
    assignments: {},
    span: { start: 0, end: 0 },
    provenance: { route: ["direct"] },
    inPipeline: false,
    processEffect: "none",
  }).kind;
}

async function loadTeaPolicy(file: string): Promise<ValidatedBashPolicy> {
  const policies = await loadPolicySources([
    {
      path: fileURLToPath(new URL(`./${file}`, import.meta.url)),
      scope: "global",
    },
  ]);
  const policy = policies.policies[0];
  if (policy === undefined) throw new Error(`failed to load ${file}`);
  return policy;
}

policyTest.test("direct issues parent permits only its optional detail and defers child routes", ({ policy }) => {
  expect(directDecision(policy, ["issues"])).toBe("allow");
  expect(directDecision(policy, ["issue", "42"])).toBe("allow");

  for (const argv of [
    ["issues", "list"],
    ["issues", "create", "title"],
    ["issues", "--unknown"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

for (const command of [
  "tea issues --repo owner/repo create title",
  "tea pulls --repo owner/repo create title",
  "tea labels --repo owner/repo delete bug",
  "tea milestones --repo owner/repo create v1",
  "tea milestones --repo owner/repo issues v1 add 42",
  "tea releases --repo owner/repo create v1",
  "tea releases --repo owner/repo assets v1 delete artifact.tar.gz",
]) {
  policyTest.test(
    `aggregate profile defers mutation after parent routing flags: ${command}`,
    profile,
    ({ evaluate }) => {
      expect(evaluate(command).decision, command).toBe("defer");
    },
  );
}

policyTest.test(
  "aggregate profile allows read aliases after supported generic option forms",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea issues --repo owner/repo list",
      "tea issue --repo=owner/repo ls",
      "tea i -r owner/repo list",
      "tea issues -l account ls",
      "tea issues --comments list",
      "tea issue list --comments=false",
    ])
      expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.test("issue list permits every documented filter and output option form", profile, ({ evaluate }) => {
  for (const [option, value] of issueListLongOptions) {
    for (const command of [`tea issues list ${option} ${value}`, `tea issue ${option}=${value} ls`])
      expect(evaluate(command).decision, command).toBe("allow");
  }

  for (const [option, value] of issueListShortOptions) {
    for (const command of [`tea i list ${option} ${value}`]) expect(evaluate(command).decision, command).toBe("allow");
  }
});

policyTest.test("issue list permits repeated interleaved filters with supported forms", profile, ({ evaluate }) => {
  for (const command of [
    "tea issues --state open list --state=closed -k bug --labels=bug,help-wanted -L urgent -p 2 --page=3",
    "tea issue --repo owner/repo list --output=json --fields=index,title --owner acme --org=platform",
    "tea i --remote origin --limit 10 ls -u 2026-12-31 --from=2026-01-01 -m release-1",
  ])
    expect(evaluate(command).decision, command).toBe("allow");
});

policyTest.test("aggregate profile defers unsafe issue invocations", profile, ({ evaluate }) => {
  for (const command of [
    "tea issues --unknown list",
    "tea issues -z list",
    "tea issues list --state",
    "tea issues list -k",
    "tea issues list --owner",
    "tea issues list --limit",
    "tea issues list --comments false",
    "tea issues list unexpected",
    "tea issues create --state open title",
    "FOO=bar tea issues list",
    "tea issues list > out",
    "/usr/bin/tea issues list",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.test("aggregate profile defers each reviewed leaf's surplus bare operand", profile, ({ evaluate }) => {
  for (const command of [
    "tea issues list extra",
    "tea pulls list extra",
    "tea labels list extra",
    "tea milestones list extra",
    "tea releases list extra",
    "tea logins list extra",
    "tea pulls review-comments 42 extra",
    "tea releases assets list v1 extra",
    "tea logins status primary secondary",
  ])
    expect(evaluate(command).decision, command).toBe("defer");
});

policyTest.test("reviewed leaf policies directly defer surplus bare operands", async () => {
  for (const [file, argv] of [
    ["issues-list.policy.json", ["issues", "list", "extra"]],
    ["pulls-list.policy.json", ["pulls", "list", "extra"]],
    ["labels-list.policy.json", ["labels", "list", "extra"]],
    ["milestones-list.policy.json", ["milestones", "list", "extra"]],
    ["releases-list.policy.json", ["releases", "list", "extra"]],
    ["logins-list.policy.json", ["logins", "list", "extra"]],
    ["pulls-review-comments.policy.json", ["pulls", "review-comments", "42", "extra"]],
    ["releases-assets-list.policy.json", ["releases", "assets", "list", "v1", "extra"]],
    ["logins-status.policy.json", ["logins", "status", "primary", "secondary"]],
  ] as const) {
    const policy = await loadTeaPolicy(file);
    expect(directDecision(policy, argv), `${file}: ${argv.join(" ")}`).toBe("defer");
  }
});

policyTest.test("issues-list policy directly requires complete known option forms", async () => {
  const policy = await loadTeaPolicy("issues-list.policy.json");
  for (const argv of [
    ["issues", "list", "--state"],
    ["issues", "list", "-k"],
    ["issues", "list", "--owner"],
    ["issues", "list", "--limit"],
    ["issues", "list", "--comments", "false"],
    ["issues", "list", "--unknown", "value"],
    ["issues", "list", "unexpected"],
    ["issues", "create", "--state", "open", "title"],
  ])
    expect(directDecision(policy, argv), argv.join(" ")).toBe("defer");
});

policyTest.test("milestones list directly enforces its missing, exact, and extra operand matrix", async () => {
  const policy = await loadTeaPolicy("milestones-list.policy.json");
  expect(directDecision(policy, ["milestones"])).toBe("defer");
  expect(directDecision(policy, ["milestones", "list"])).toBe("allow");
  expect(directDecision(policy, ["milestones", "list", "v1"])).toBe("defer");
});

policyTest.property(
  "issue list options retain supported forms, ordering, and repetition",
  { ...profile, cases: 128, seed: 47 },
  ({ evaluate, random }) => {
    const parent = random.pick(["issues", "issue", "i"]);
    const child = random.pick(["list", "ls"]);
    const [longOption, longValue] = random.pick(issueListLongOptions);
    const [shortOption, shortValue] = random.pick(issueListShortOptions);
    const first = random.pick([`${longOption} ${longValue}`, `${longOption}=${longValue}`]);
    const second = random.pick([`${shortOption} ${shortValue}`]);
    const words = ["tea", parent, child];
    words.splice(random.integer(2, words.length), 0, first);
    words.splice(random.integer(2, words.length), 0, second);
    if (random.integer(0, 1) === 1) words.splice(random.integer(2, words.length), 0, first);
    const command = words.join(" ");
    expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.property(
  "issue list defers generated missing values and surplus operands",
  { ...profile, cases: 128, seed: 53 },
  ({ evaluate, random }) => {
    const [longOption, longValue] = random.pick(issueListLongOptions);
    const [shortOption, shortValue] = random.pick(issueListShortOptions);
    const missing = random.pick([longOption, shortOption]);
    const option = random.pick([`${longOption} ${longValue}`, `${shortOption} ${shortValue}`]);
    const missingCommand = `tea issues list ${missing}`;
    const extraCommand = `tea issues list ${option} extra-${random.integer(0, 999_999)}`;
    expect(evaluate(missingCommand).decision, missingCommand).toBe("defer");
    expect(evaluate(extraCommand).decision, extraCommand).toBe("defer");
  },
);

policyTest.property(
  "reviewed leaf cardinalities retain generic options without treating their values as operands",
  { ...profile, cases: 96, seed: 59 },
  ({ evaluate, random }) => {
    const leaf = random.pick([
      ["issues", "list"],
      ["pulls", "list"],
      ["labels", "list"],
      ["milestones", "list"],
      ["releases", "list"],
      ["logins", "list"],
      ["pulls", "review-comments", "42"],
      ["releases", "assets", "list", "v1"],
      random.pick([
        ["logins", "status"],
        ["logins", "status", "primary"],
      ]),
    ]);
    const option = random.pick([
      ["--login", "account"],
      ["--login=account"],
      ["-l", "account"],
      ["--repo", "owner/repo"],
      ["--repo=owner/repo"],
      ["-r", "owner/repo"],
      ["--remote", "origin"],
      ["--remote=origin"],
      ["-R", "origin"],
      ["--output", "json"],
      ["--output=json"],
      ["-o", "json"],
    ]);
    const words = ["tea", ...leaf];
    words.splice(random.integer(2, words.length), 0, ...option);
    const command = words.join(" ");
    expect(evaluate(command).decision, command).toBe("allow");
  },
);

policyTest.property(
  "Tea policies defer generated root options, attached shorts, and clusters",
  { ...profile, cases: 128, seed: 83 },
  ({ evaluate, random }) => {
    const [, command] = random.pick(teaProfileRepresentatives);
    const route = command.slice("tea ".length);
    const prefix = random.pick(["--login account", "--login=account", "-laccount", "-rlaccount"]);
    const source = `tea ${prefix} ${route}`;
    expect(evaluate(source).decision, source).toBe("defer");
  },
);

policyTest.test("all configured Tea routes defer root options and unsupported short forms", profile, ({ evaluate }) => {
  for (const [, command] of teaProfileRepresentatives) {
    const route = command.slice("tea ".length);
    for (const prefix of ["--login account", "--login=account", "-laccount", "-rlaccount"]) {
      const source = `tea ${prefix} ${route}`;
      expect(evaluate(source).decision, source).toBe("defer");
    }
  }
});

policyTest.test("Tea policy declarations use only pinned parser forms and post-route availability", async () => {
  for (const [file] of teaProfileRepresentatives) {
    const pathname = fileURLToPath(new URL(`./${file}`, import.meta.url));
    const document = JSON.parse(await readFile(pathname, "utf8")) as {
      options: Record<string, { forms: string[]; availableIn: string[] | "*"; names: string[]; value: string }>;
    };
    const policy = await loadTeaPolicy(file);

    for (const option of Object.values(document.options)) {
      expect(option.forms).not.toContain("attachedShort");
      expect(option.forms).not.toContain("cluster");
      expect(option.availableIn).not.toBe("*");
      expect(option.availableIn).not.toContain("start");

      const argv = [option.names[0]!];
      if (option.value !== "absent") argv.push("value");
      expect(directDecision(policy, argv), `${file}: ${argv.join(" ")}`).toBe("defer");
    }
  }
});

policyTest.test("installed Tea help is a non-network parser source smoke test", async () => {
  const process = Bun.spawn(["tea", "--help"], {
    stdout: "pipe",
    stderr: "pipe",
  });
  expect(await process.exited).toBe(0);
});

policyTest.test(
  "Tea preserves valid separate and long-equals forms while deferring short equals",
  profile,
  ({ evaluate }) => {
    for (const command of [
      "tea issues --repo owner/repo list",
      "tea issues --repo=owner/repo list",
      "tea issues -r owner/repo list",
      "tea issues list --keyword bug",
      "tea issues list --keyword=bug",
      "tea issues list -k bug",
    ])
      expect(evaluate(command).decision, command).toBe("allow");

    for (const command of [
      "tea issues -r=owner/repo list",
      "tea issues list -k=bug",
      "tea issues list -kbug",
      "tea issues -rl owner/repo list",
    ])
      expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.property(
  "reviewed leaves defer generated surplus bare operands",
  { ...profile, cases: 96, seed: 61 },
  ({ evaluate, random }) => {
    const leaf = random.pick([
      ["issues", "list"],
      ["pulls", "list"],
      ["labels", "list"],
      ["milestones", "list"],
      ["releases", "list"],
      ["logins", "list"],
      ["pulls", "review-comments", "42"],
      ["releases", "assets", "list", "v1"],
      ["logins", "status", "primary"],
    ]);
    const command = `tea ${leaf.join(" ")} extra-${random.integer(0, 999_999)}`;
    expect(evaluate(command).decision, command).toBe("defer");
  },
);

policyTest.test("direct Tea allow paths require an external execution target", async () => {
  const policy = await loadTeaPolicy("labels.policy.json");
  expect(directDecision(policy, ["labels"])).toBe("allow");
  expect(directDecision(policy, ["labels"], "shell-function")).toBe("defer");
});

policyTest.property(
  "aggregate profile permits external Tea aliases but defers local Tea functions",
  { ...profile, cases: 96, seed: 79 },
  ({ evaluate, random }) => {
    const command = random.pick([
      "tea labels",
      "tea label",
      "tea issues",
      "tea i list",
      "tea pulls ls",
      "tea pr review-comments 42",
      "tea actions secrets list",
      "tea action workflow get deploy",
      "tea completion bash",
      "tea whoami",
    ]);
    const definition = random.pick(["tea() { x=1; }", "function tea { x=1; }"]);

    expect(evaluate(command).decision, command).toBe("allow");
    expect(evaluate(`${definition}; ${command}`).decision, `${definition}; ${command}`).toBe("defer");
  },
);

policyTest.test(
  "full read-only profile covers every configured Tea policy representative",
  profile,
  ({ evaluate, policySet }) => {
    const configuredPolicies = new Set(policySet.sources.map((source) => basename(source.canonicalPath)));
    expect(configuredPolicies).toEqual(new Set(teaProfileRepresentatives.map(([policy]) => policy)));
    expect(teaProfileRepresentatives).toHaveLength(65);
    expect(teaProfileRepresentatives.filter(([, , decision]) => decision === "allow")).toHaveLength(63);

    for (const [policy, command, expected] of teaProfileRepresentatives) {
      const result = evaluate(command);
      expect(result.decision, `${policy}: ${command}`).toBe(expected);
      expect(teaInvocation(result.events, "external-path"), `${policy}: ${command}`).toBeDefined();
    }
  },
);

policyTest.test(
  "permitted Tea routes compose with the env transparent wrapper without losing argv or provenance",
  transparentWrapperProfile,
  ({ evaluate }) => {
    for (const [, command, expected] of teaProfileRepresentatives) {
      if (expected !== "allow") continue;
      const direct = evaluate(command);
      const wrappedSource = `env MODE=test ${command}`;
      const wrapped = evaluate(wrappedSource);
      const directTea = teaInvocation(direct.events, "external-path");
      const wrappedTea = teaInvocation(wrapped.events, "external-path");
      const env = wrapped.events.find(
        (event): event is InvocationView =>
          event.kind === "invocation" && event.executable?.kind === "known" && event.executable.value === "env",
      );

      expect(directTea, command).toBeDefined();
      expect(wrappedTea, wrappedSource).toBeDefined();
      expect(env, wrappedSource).toBeDefined();
      expect(wrapped.decision, wrappedSource).toBe("allow");
      expect(knownArgv(wrappedTea!)).toEqual(knownArgv(directTea!));
      expect(wrappedTea!.provenance.route).toEqual([...directTea!.provenance.route, "transparent-wrapper"]);
    }
  },
);

policyTest.property(
  "generated transparent env wrappers preserve allowable Tea child routing",
  { ...transparentWrapperProfile, cases: 128, seed: 101 },
  ({ evaluate, random }) => {
    const [, command] = random.pick(teaProfileRepresentatives.filter(([, , expected]) => expected === "allow"));
    const prefix = random.pick(["env", "env MODE=test", "env -- MODE=test"]);
    const direct = evaluate(command);
    const wrappedSource = `${prefix} ${command}`;
    const wrapped = evaluate(wrappedSource);
    const directTea = teaInvocation(direct.events, "external-path");
    const wrappedTea = teaInvocation(wrapped.events, "external-path");

    expect(wrapped.decision, wrappedSource).toBe("allow");
    expect(wrappedTea, wrappedSource).toBeDefined();
    expect(directTea, command).toBeDefined();
    expect(knownArgv(wrappedTea!)).toEqual(knownArgv(directTea!));
    expect(wrappedTea!.provenance.route).toEqual([...directTea!.provenance.route, "transparent-wrapper"]);
  },
);

policyTest.test("Tea functions shadow every configured direct route", profile, ({ evaluate }) => {
  for (const definition of ["tea() { x=1; }", "function tea { x=1; }"] as const) {
    for (const [policy, command] of teaProfileRepresentatives) {
      const source = `${definition}; ${command}`;
      const result = evaluate(source);
      expect(result.decision, `${policy}: ${source}`).toBe("defer");
      expect(teaInvocation(result.events, "shell-function"), `${policy}: ${source}`).toBeDefined();
    }
  }
});
