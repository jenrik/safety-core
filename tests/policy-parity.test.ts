import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import githubHttp from "./fixtures/code-policies/github-http.policy.ts";
import genericReadOnly from "./fixtures/code-policies/generic-read-only.policy.ts";
import ghApi from "./fixtures/code-policies/gh-api.policy.ts";
import { createGhPrCreatePolicy } from "./fixtures/code-policies/gh-pr-create.policy.ts";
import ghReadOnly from "./fixtures/code-policies/gh-read-only.policy.ts";
import helmReadOnly from "./fixtures/code-policies/helm-read-only.policy.ts";
import kubectl from "./fixtures/code-policies/kubectl.policy.ts";
import secretRead from "./fixtures/code-policies/secret-read.policy.ts";
import strictReadOnly from "./fixtures/code-policies/strict-read-only.policy.ts";
import unsupportedShellSource from "./fixtures/code-policies/unsupported-shell-source.policy.ts";
import { analyzeBashWithPolicies, initBashParser, type LoadedBashPolicy, type ValidatedBashPolicy } from "../src/index.ts";
import { compilePolicyDocument } from "../src/policy/dsl/compile.ts";
import { createDslPolicy } from "../src/policy/dsl/evaluate.ts";
import { parsePolicyDocument } from "../src/policy/dsl/validate.ts";
import { analyzeSecretReadInvocation } from "../src/bash/policies/secrets.ts";
import { GH_READ_ONLY_RULES } from "../src/bash/policies/gh-read-only.ts";
import { STRICT_READ_ONLY_COMMANDS } from "../src/bash/policies/read-only-data.ts";
import { renderGhPrCreateDslPolicy } from "../scripts/render-gh-pr-create-dsl.mjs";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-parity-"));
const policies = Object.freeze([
  loaded("/trusted/secret-read.policy.mjs", secretRead),
  loaded("/trusted/github-http.policy.mjs", githubHttp),
  loaded("/trusted/kubectl.policy.mjs", kubectl),
  loaded("/trusted/unsupported-shell-source.policy.mjs", unsupportedShellSource),
  loaded("/trusted/generic-read-only.policy.mjs", genericReadOnly),
]);

const guardPairs = Object.freeze([
  ["secret-read", secretRead, dsl("secret-read")],
  ["github-http", githubHttp, dsl("github-http")],
  ["kubectl", kubectl, dsl("kubectl")],
  ["unsupported-shell-source", unsupportedShellSource, dsl("unsupported-shell-source")],
] as const);

const dslPolicies = Object.freeze(guardPairs.map(([, , policy]) => policy as ValidatedBashPolicy));
const codeGuardPolicies = Object.freeze(guardPairs.map(([name, policy]) => loaded(`/trusted/${name}.policy.mjs`, policy)));
const prConfiguration = Object.freeze({ allowedRepositories: ["github.com/acme/widgets"], allowedOrganizations: ["trusted-org"] });
const codePr = loaded("/trusted/gh-pr-create.policy.mjs", createGhPrCreatePolicy(prConfiguration));
const dslPr = createDslPolicy(
  compilePolicyDocument(parsePolicyDocument(renderGhPrCreateDslPolicy(prConfiguration))),
  "/trusted/gh-pr-create.policy.json",
) as ValidatedBashPolicy;

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

describe("baseline guard code-policy parity", () => {
  test("differential: every current guard corpus outcome matches its DSL source", () => {
    for (const source of guardCorpus()) {
      expectPolicyParity(source);
    }
  });

  test("regression: walker-projected protected reader invocations retain code-policy inputs", () => {
    const event = analyzeBashWithPolicies({ source: "cat credentials.json", policies: dslPolicies }).events[0];
    expect(event).toMatchObject({ kind: "invocation", executable: { kind: "known", value: "cat" }, argv: [{ kind: "known", value: "credentials.json" }] });
    if (event?.kind !== "invocation") throw new Error("expected invocation event");
    expect(analyzeSecretReadInvocation(event)).toMatchObject({ kind: "deny" });
    expectPolicyParity("cat credentials.json");
    const selected = analyzeBashWithPolicies({ source: "cat credentials.json", policies: dslPolicies }).traces
      .find((trace) => trace.source.canonicalPath.endsWith("secret-read.policy.json"));
    expect(selected?.decision).toMatchObject({ kind: "deny" });
  });

  test("regression: a protected later kubectl resource retains its audited defer", () => {
    const source = "kubectl get pod secrets/application";
    expectPolicyParity(source);
    const result = analyzeBashWithPolicies({ source, policies: dslPolicies });
    expect(result.traces.find((trace) => trace.source.canonicalPath.endsWith("kubectl.policy.json"))?.decision)
      .toMatchObject({ kind: "defer", audit: { invocation: expect.any(Object) } });
  });

  test("regression: kubectl get classifies only positional resource operands", () => {
    expectPolicyParity("kubectl get pod secret");
    expectPolicyParity("kubectl get pod configmap/app");
    expectPolicyParity("kubectl get pod --namespace secret");
  });

  test("regression: finite GitHub endpoint mappings preserve legacy steering", () => {
    const endpoints = [
      "/repos/acme/widgets/issues/42", "/repos/acme/widgets/issues/not-a-number",
      "/repos/acme/widgets/pulls/17", "/repos/acme/widgets/pulls",
      "/repos/acme/widgets/releases/latest", "/repos/acme/widgets/releases/tags/v1.2.3", "/repos/acme/widgets/releases",
      "/repos/acme/widgets/actions/runs/9", "/repos/acme/widgets/actions/runs", "/repos/acme/widgets/actions/workflows",
      "/repos/acme/widgets/labels", "/repos/acme/widgets",
      "/search/issues", "/search/repositories", "/search/code", "/gists/123",
      "/unmapped/route",
    ];

    for (const endpoint of endpoints) expectPolicyParity(`curl https://api.github.com${endpoint}`, endpoint);
    expectPolicyParity("curl https://raw.githubusercontent.com/acme/widgets/main/src/nested/file.ts");
    expectPolicyParity("curl https://raw.githubusercontent.com/acme/widgets/main");
  });

  test("differential: exact-basename DSL selectors only select matching kubectl invocations", () => {
    const dsl = analyzeBashWithPolicies({ source: "echo https://api.github.com/user; cat README.md", policies: dslPolicies });

    expect(dsl.traces.filter((trace) => trace.source.canonicalPath.includes("kubectl"))).toHaveLength(0);
  });

  test("property: generated argument, wrapper, and source-order cases stay differential", () => {
    const violations = [
      "cat credentials.json",
      "curl https://api.github.com/user",
      "kubectl view-secret application",
    ];
    const safe = ["cat README.md", "curl https://example.test", "kubectl get pods"];
    const wrappers = [
      (command: string) => command,
      (command: string) => `env -i ${command}`,
      (command: string) => `strace -f ${command}`,
      (command: string) => `sh -c '${command}'`,
    ];
    for (let seed = 0; seed < 192; seed++) {
      const violation = violations[seed % violations.length]!;
      const prefix = safe[(seed * 7) % safe.length]!;
      const suffix = violations[(seed * 11) % violations.length]!;
      const source = `${prefix}; ${wrappers[seed % wrappers.length]!(violation)}; ${suffix}`;
      expectPolicyParity(source, `${seed}: ${source}`);
    }
  });

  test("property: GitHub numeric route prefixes and raw path suffixes stay differential", () => {
    for (let seed = 0; seed < 96; seed++) {
      const identifier = `${seed}${seed % 3 === 0 ? "suffix" : ""}`;
      const nested = Array.from({ length: seed % 5 + 1 }, (_, index) => `part-${index}`).join("/");
      expectPolicyParity(`curl https://api.github.com/repos/acme/widgets/issues/${identifier}/detail`, `issue ${seed}`);
      expectPolicyParity(`curl https://api.github.com/repos/acme/widgets/actions/runs/${identifier}/logs`, `run ${seed}`);
      expectPolicyParity(`curl https://raw.githubusercontent.com/acme/widgets/main/${nested}`, `raw ${seed}`);
    }
  });

  test("property: baseline secret grammar remains case-insensitive for readers and redirects", () => {
    const paths = [".env", "secrets.json", "id_rsa", "CREDENTIALS.JSON", "service-account-prod.json", "prod.SECRETS.YAML"];
    for (let seed = 0; seed < 96; seed++) {
      const path = paths[seed % paths.length]!;
      const mixed = path.split("").map((character, index) => (seed + index) % 2 === 0 ? character.toUpperCase() : character.toLowerCase()).join("");
      expectPolicyParity(`cat ${mixed}`, `reader case ${seed}`);
      expectPolicyParity(`wc < ${mixed}`, `redirect case ${seed}`);
    }
  });

  test("property: domain-token fallback and kubectl flag consumption match the baseline", () => {
    const github = ["api.github.com", "--url=https://api.github.com/user", "RAW.GITHUBUSERCONTENT.COM", "--url=raw.githubusercontent.com/file"];
    const flags = ["--bogus", "--namespace default", "--output=json", "-n default", "--request-timeout 1s"];
    for (let seed = 0; seed < 96; seed++) {
      expectPolicyParity(`curl ${github[seed % github.length]!}`, `domain token ${seed}`);
      expectPolicyParity(`kubectl get ${flags[seed % flags.length]!} secret`, `kubectl flag ${seed}`);
    }
  });

  test("matches baseline denials through wrappers, nested source, and execution gaps", () => {
    for (const source of [
      "cat credentials.json",
      "strace -f curl https://api.github.com/repos/acme/widgets/issues",
      "sh -c 'kubectl view-secret application'",
      "fish -c true",
      'fish -c "$(echo source)"',
      "< credentials.json",
      "(cat) < credentials.json",
      "{ cat; } < credentials.json",
    ]) {
      const legacy = analyzeBashWithPolicies({ source, policies });
      const generic = analyzeBashWithPolicies({ source, policies });

      expect(legacy.decision, source).toBe("deny");
      expect(generic.decision, source).toBe("deny");
      const trace = generic.traces.find((candidate) => candidate.decision.kind === "deny");
      expect(trace, source).toBeDefined();
      expect(trace?.decision, source).toMatchObject({
        kind: "deny",
        reason: legacy.traces.find((candidate) => candidate.decision.kind === "deny")?.decision.kind === "deny"
          ? legacy.traces.find((candidate) => candidate.decision.kind === "deny")?.decision.reason : [],
      });
      expect(trace?.decision, source).toMatchObject({
        audit: trace?.event.kind === "invocation" ? { invocation: trace.event } : { gap: trace?.event },
      });
    }
  });

  test("safe guard paths never authorize and a later denial dominates indeterminate work", () => {
    for (const source of [
      "cat README.md",
      "curl https://example.test",
      "kubectl get pods",
      "unknown-command; kubectl get secret app; cat credentials.json",
    ]) {
      const generic = analyzeBashWithPolicies({ source, policies });
      expect(generic.decision, source).toBe(source.endsWith("credentials.json") ? "deny" : "defer");
      expect(generic.traces.every((trace) => trace.decision.kind !== "allow"), source).toBeTrue();
    }
  });

  test("retains generic policy denials for binding-derived source and kubectl audit values", () => {
    const bindingSource = analyzeBashWithPolicies({ source: "SCRIPT='cat credentials.json'; sh -c \"$SCRIPT\"", policies });
    const kubectlSource = analyzeBashWithPolicies({ source: "kubectl get secret application", policies });

    expect(bindingSource.decision).toBe("deny");
    expect(bindingSource.traces.find((trace) => trace.decision.kind === "deny")?.event.provenance.route)
      .toContain("binding-derived-script");
    const kubectlDecision = kubectlSource.traces.find((trace) => trace.decision.kind === "defer")?.decision;
    expect(kubectlDecision).toMatchObject({ kind: "defer" });
    if (kubectlDecision?.kind === "defer") {
      expect((kubectlDecision.audit?.invocation as { readonly argv: readonly { readonly value: string }[] }).argv)
        .toEqual([{ kind: "known", value: "get" }, { kind: "known", value: "secret" }, { kind: "known", value: "application" }]);
    }
  });

  test("projects early structural boundaries into generic policy events", () => {
    const fish = analyzeBashWithPolicies({ source: 'fish -c "$(echo source)"', policies });
    const redirect = analyzeBashWithPolicies({ source: "{ cat; } < credentials.json", policies });

    expect(fish.events).toContainEqual(expect.objectContaining({ kind: "execution-gap", reason: "unsupported-shell-source" }));
    expect(redirect.events).toContainEqual(expect.objectContaining({
      kind: "invocation",
      executable: null,
      redirects: [{ kind: "input", target: { kind: "known", value: "credentials.json" } }],
    }));
  });

  test("property: wrapper and source order preserve every baseline denial", () => {
    const blocked = ["cat credentials.json", "curl https://api.github.com/user", "kubectl view-secret app"];
    const wrappers = [(source: string) => source, (source: string) => `env -i ${source}`, (source: string) => `sh -c '${source}'`];

    for (let seed = 0; seed < 96; seed++) {
      const source = wrappers[seed % wrappers.length]!(blocked[seed % blocked.length]!);
      expect(analyzeBashWithPolicies({ source: `unknown-command; ${source}`, policies }).decision, `${seed}: ${source}`).toBe("deny");
    }
  });

  test("allows generic compound reads without foreign policy deferrals", () => {
    const result = analyzeBashWithPolicies({
      source: "git diff HEAD; sha256sum README.md",
      policies,
      initialEnvironment: { kind: "verified", values: {} },
    });

    expect(result.decision).toBe("allow");
  });
});

describe("permission code-policy parity", () => {
  test("differential: generic and Helm grammar, environment routes, and qualified paths", () => {
    for (const source of [
      "git diff HEAD", "git diff --ext-diff", "git branch --list", "git branch --list topic",
      "sha256sum README.md", "tea --help", "tea help", "helm search repo nginx", "helm show chart nginx",
      "helm show chart nginx --debug", "./git diff HEAD", "GIT_EXTERNAL_DIFF=helper git diff HEAD",
    ]) {
      expectPermissionParity(source, genericReadOnly, dsl("generic-read-only"));
      expectPermissionParity(source, helmReadOnly, dsl("helm-read-only"));
    }
  });

  test("differential: every strict executable path, option form, and unsafe operand", () => {
    for (const [executable, paths] of Object.entries(STRICT_READ_ONLY_COMMANDS)) {
      const policy = dsl(`strict-${executable}`);
      for (const path of paths) {
        const command = `${executable} ${path.replaceAll(":", " ")}`;
        expectPermissionParity(command, strictReadOnly, policy);
        expectPermissionParity(`${command} --unknown`, strictReadOnly, policy);
        expectPermissionParity(`${command} credentials.json`, strictReadOnly, policy);
      }
    }
  });

  test("property: strict audited paths preserve parity across option positions and execution routes", () => {
    const commands = Object.entries(STRICT_READ_ONLY_COMMANDS).flatMap(([executable, paths]) =>
      [...paths].map((path) => `${executable} ${path.replaceAll(":", " ")}`));
    for (let seed = 0; seed < 192; seed++) {
      const command = commands[seed % commands.length]!;
      const [executable, ...arguments_] = command.split(" ");
      const variants = [
        command,
        `${executable} --unknown ${arguments_.join(" ")}`,
        `${command} --unknown`,
        `${executable} ${arguments_.join(" ")} credentials.json`,
        `GIT_EXTERNAL_DIFF=helper ${command}`,
        `./${command}`,
      ];
      expectPermissionParity(variants[seed % variants.length]!, strictReadOnly, dsl(`strict-${executable}`));
    }
  });

  test("differential: GH inventory and aliases remain owned without authorizing unknown routes", () => {
    for (const rule of GH_READ_ONLY_RULES) {
      for (const form of [rule.path, ...rule.aliases]) {
        expectPermissionParity(`gh ${form.join(" ")}`, ghReadOnly, dsl("gh-read-only"));
        expectPermissionParity(`gh ${form.join(" ")} --unknown`, ghReadOnly, dsl("gh-read-only"));
      }
    }
    for (const source of ["gh extension list", "gh alias list", "gh unknown", "./gh issue list", "GH_HOST=example.test gh issue list"]) {
      expectPermissionParity(source, ghReadOnly, dsl("gh-read-only"));
    }
  }, 30_000);

  test("differential: GH API methods, endpoint classes, parser forms, and environment routes", () => {
    for (const source of [
      "gh api user", "gh api user --method=HEAD", "gh api user -XPOST", "gh api user -X POST",
      "gh api user -f name=value", "gh api user -f invalid -X GET", "gh api user -F name=value -X GET", "gh api user -F name=@body", "gh api user --input body", "gh api graphql -X GET",
      "gh api /repos/acme/widgets/issues/42", "gh api user --verbose", "gh --repo acme/widgets api user",
      "GH_PAGER=cat gh api user", "./gh api user", "gh api user --method DELETE",
    ]) expectPermissionParity(source, ghApi, dsl("gh-api"), { GH_PAGER: "cat" });
    expectPermissionParity("gh api user", ghApi, dsl("gh-api"), {
      GH_PAGER: "cat",
      __SAFETY_CORE_INHERITED_GH_PAGER: "less",
    });
  });

  test("differential: generated PR allowlist validates repository targets and noninteractive grammar", () => {
    for (const source of [
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill",
      "export GH_PROMPT_DISABLED=1; gh pr new --repo github.com/trusted-org/other --title title --body body",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo acme/widgets --fill",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/attacker/widgets --fill",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --editor",
      "gh pr create --repo github.com/acme/widgets --fill",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill extra",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --repo github.com/acme/widgets --fill",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill --fill",
      "export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --base main --base main --fill",
      "export GH_PROMPT_DISABLED=1; eval 'gh pr create --repo github.com/acme/widgets --fill'",
      "export GH_PROMPT_DISABLED=1; sh -c 'gh pr create --repo github.com/acme/widgets --fill'",
      "export GH_PROMPT_DISABLED=1; SCRIPT='gh pr create --repo github.com/acme/widgets --fill'; sh -c \"$SCRIPT\"",
      "export GH_PROMPT_DISABLED=1; gh api user",
    ]) expectPermissionParity(source, codePr, dslPr);
  });

  test("trace-level: GH policies retain delegated API and PR ownership per invocation", () => {
    const policies = [dsl("gh-read-only"), dsl("gh-api"), dslPr];
    const result = analyzeBashWithPolicies({
      source: "gh api user; export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill",
      policies,
      initialEnvironment: { kind: "verified", values: { GH_PAGER: "cat" } },
    });

    expect(result.decision).toBe("allow");
    expect(traceDecisions(result)).toEqual([
      { eventIndex: 0, source: "gh-read-only.policy.json", decision: "ignore" },
      { eventIndex: 0, source: "gh-api.policy.json", decision: "allow" },
      { eventIndex: 0, source: "gh-pr-create.policy.json", decision: "ignore" },
      { eventIndex: 1, source: "gh-read-only.policy.json", decision: "ignore" },
      { eventIndex: 1, source: "gh-api.policy.json", decision: "ignore" },
      { eventIndex: 1, source: "gh-pr-create.policy.json", decision: "allow" },
    ]);
  });

  test("trace-level: PR interpreter provenance is denied by the dedicated policy", () => {
    const result = analyzeBashWithPolicies({
      source: "export GH_PROMPT_DISABLED=1; eval 'gh pr create --repo github.com/acme/widgets --fill'",
      policies: [dsl("gh-read-only"), dsl("gh-api"), dslPr],
    });

    expect(result.decision).toBe("deny");
    expect(traceDecisions(result).filter((trace) => trace.decision === "deny"))
      .toEqual([{ eventIndex: 1, source: "gh-pr-create.policy.json", decision: "deny" }]);
  });

  test("renders a canonical PR allowlist source and rejects malformed identifiers", () => {
    const source = renderGhPrCreateDslPolicy({
      allowedRepositories: ["GitHub.com/Acme/Widgets", "github.com/acme/another"],
      allowedOrganizations: ["trusted-org", "github.com/another-org"],
    });
    const reordered = renderGhPrCreateDslPolicy({
      allowedRepositories: ["github.com/acme/another", "GitHub.com/Acme/Widgets"],
      allowedOrganizations: ["github.com/another-org", "trusted-org"],
    });
    expect(source).toBe(reordered);
    expect(createHash("sha256").update(source).digest("hex")).toBe("3bf526cc010cdaa662f504ef2c6d7b489658e9ef0cb6bd734e7cc06aa80ed28a");
    expect(() => parsePolicyDocument(source)).not.toThrow();
    for (const options of [
      { allowedRepositories: ["acme"], allowedOrganizations: [] },
      { allowedRepositories: ["github.com/acme/widgets/extra"], allowedOrganizations: [] },
      { allowedRepositories: ["github.com/acme/widgets", "github.com/acme/widgets"], allowedOrganizations: [] },
      { allowedRepositories: ["github.com/acme/widgets"], allowedOrganizations: ["invalid org"] },
    ]) expect(() => renderGhPrCreateDslPolicy(options)).toThrow(TypeError);
  });

  test("property: aliases, option permutations, qualified paths, and unsafe routes remain differential", () => {
    const apiOptions = [
      "-X GET", "--method=HEAD", "-f name=value", "--verbose", "--header X:Y",
      "-f name=value -X GET", "-X GET -f name=value",
    ];
    const prOptions = [
      "--repo github.com/acme/widgets --fill", "--fill --repo github.com/acme/widgets",
      "-Rgithub.com/acme/widgets -f", "-f -R github.com/acme/widgets",
      "--repo=github.com/acme/widgets --title=title --body=body", "--editor --repo github.com/acme/widgets",
      "--repo github.com/acme/widgets --body-file body.md",
    ];
    for (let seed = 0; seed < 192; seed++) {
      const api = apiOptions[seed % apiOptions.length]!;
      const pr = prOptions[(seed * 7) % prOptions.length]!;
      const prefix = seed % 3 === 0 ? "./" : "";
      expectPermissionParity(`${prefix}gh api user ${api}`, ghApi, dsl("gh-api"), { GH_PAGER: "cat" });
      expectPermissionParity(`export GH_PROMPT_DISABLED=1; ${prefix}gh pr create ${pr}`, codePr, dslPr);
    }
  });

  test("property: combined GH policies preserve denial dominance and specialized ownership", () => {
    const codePolicies = [
      loaded("/trusted/gh-read-only.policy.mjs", ghReadOnly),
      loaded("/trusted/gh-api.policy.mjs", ghApi),
      codePr,
    ];
    const dslPolicySet = [dsl("gh-read-only"), dsl("gh-api"), dslPr];
    const routes = [
      "gh api user; export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill",
      "gh api graphql; export GH_PROMPT_DISABLED=1; gh pr create --repo github.com/acme/widgets --fill",
      "gh api user; gh pr create --repo github.com/acme/widgets --fill",
      "gh api user; export GH_PROMPT_DISABLED=1; eval 'gh pr create --repo github.com/acme/widgets --fill'",
    ];
    for (let seed = 0; seed < 128; seed++) {
      expectPolicySetParity(routes[seed % routes.length]!, codePolicies, dslPolicySet, { GH_PAGER: "cat" });
    }
  });
});

function dsl(name: string): ValidatedBashPolicy {
  const path = new URL(`../policies/dsl/${name}.policy.json`, import.meta.url);
  return createDslPolicy(compilePolicyDocument(parsePolicyDocument(readFileSync(path, "utf8"))), path.pathname) as ValidatedBashPolicy;
}

function expectPolicyParity(source: string, label = source): void {
  const code = analyzeBashWithPolicies({ source, policies: codeGuardPolicies });
  const dsl = analyzeBashWithPolicies({ source, policies: dslPolicies });
  expect(code.events, `${label}: walker events`).toEqual(dsl.events);
  expect(selectedTraces(code.traces, code.events, ".mjs"), `${label}: selected code traces`)
    .toEqual(selectedTraces(dsl.traces, dsl.events, ".json"));
}

function expectPermissionParity(
  source: string,
  codeDefinition: Omit<LoadedBashPolicy, "source"> & { readonly apiVersion: 1 },
  dslPolicy: ValidatedBashPolicy,
  values: Readonly<Record<string, string>> = {},
): void {
  const codePolicy = "source" in codeDefinition
    ? codeDefinition as ValidatedBashPolicy
    : loaded("/trusted/permission.policy.mjs", codeDefinition);
  const options = { source, initialEnvironment: { kind: "verified" as const, values } };
  const code = analyzeBashWithPolicies({ ...options, policies: [codePolicy] });
  const dslResult = analyzeBashWithPolicies({ ...options, policies: [dslPolicy] });
  expect(dslResult.events, `${source}: events`).toEqual(code.events);
  expect(dslResult.decision, `${source}: decision`).toBe(code.decision);
}

function expectPolicySetParity(
  source: string,
  codePolicies: readonly ValidatedBashPolicy[],
  dslPolicySet: readonly ValidatedBashPolicy[],
  values: Readonly<Record<string, string>>,
): void {
  const options = { source, initialEnvironment: { kind: "verified" as const, values } };
  const code = analyzeBashWithPolicies({ ...options, policies: codePolicies });
  const dslResult = analyzeBashWithPolicies({ ...options, policies: dslPolicySet });
  expect(dslResult.events, `${source}: mixed events`).toEqual(code.events);
  expect(dslResult.decision, `${source}: mixed decision`).toBe(code.decision);
}

function traceDecisions(result: ReturnType<typeof analyzeBashWithPolicies>): readonly {
  readonly eventIndex: number;
  readonly source: string;
  readonly decision: string;
}[] {
  return result.traces.map((trace) => Object.freeze({
    eventIndex: result.events.indexOf(trace.event),
    source: trace.source.canonicalPath.split("/").at(-1)!,
    decision: trace.decision.kind,
  }));
}

function selectedTraces(
  traces: readonly { readonly source: { readonly canonicalPath: string }; readonly event: unknown; readonly decision: unknown }[],
  events: readonly unknown[],
  suffix: string,
): readonly { readonly family: string; readonly eventIndex: number; readonly decision: unknown }[] {
  return traces.map((trace) => Object.freeze({
    family: trace.source.canonicalPath.split("/").at(-1)!.replace(suffix, ""),
    eventIndex: events.indexOf(trace.event),
    decision: trace.decision,
  }));
}

function guardCorpus(): readonly string[] {
  return [
    "cat credentials.json", "cat README.md", "cat .env", "cat .ENV", "cat CREDENTIALS.JSON", "/bin/cat CREDENTIALS.JSON", "cat .env.example",
    "wc < credentials.json", "wc < .env", "wc < secrets.json", "wc < id_rsa", "< credentials.json", "{ cat; } < credentials.json",
    "curl https://api.github.com/repos/acme/widgets/issues", "curl https://API.GITHUB.COM./user", "curl --url=https://api.github.com/user", "curl api.github.com", "curl https://example.test",
    "wget https://raw.githubusercontent.com/acme/widgets/main/README.md", "echo https://api.github.com/user",
    "kubectl view-secret application", "kubectl get secret application", "kubectl get secrets", "kubectl get pods",
    "kubectl --namespace default get secret application", "kubectl get pod secrets/application", "kubectl get --bogus secret",
    "fish -c true", "fish --command=\"$(echo source)\"", "fish --version",
    "strace -f curl https://api.github.com/user", "sh -c 'kubectl view-secret application'",
    "unknown-command; cat credentials.json", "curl https://example.test; kubectl view-secret application",
  ];
}

function loaded(path: string, definition: Omit<LoadedBashPolicy, "source"> & { readonly apiVersion: 1 }): ValidatedBashPolicy {
  return Object.freeze({
    source: Object.freeze({ canonicalPath: path }),
    layer: definition.layer,
    select: definition.select,
    evaluate: definition.evaluate,
  }) as ValidatedBashPolicy;
}
