import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  STRICT_BASH_PROFILE_EXECUTABLES,
  evaluateBashGuards,
  evaluateConfiguredBash,
  initBashParser,
  type BashProfileSnapshot,
  type GhPrCreatePolicy,
} from "../src/index.ts";
import { GH_API_DEFER_ENVIRONMENT_NAMES, GH_GLOBAL_DEFER_ENVIRONMENT_NAMES, policyInitialEnvironment } from "../src/bash/policy-environment.ts";

const policy: GhPrCreatePolicy = {
  enabled: true,
  allowedRepositories: ["acme/widgets"],
  allowedOrganizations: ["trusted-org"],
};

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-bash-gh-policies-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm)
      ? packagedWasm
      : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
    join(wasmDir, "tree-sitter-bash.wasm"),
  );
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

function snapshot(overrides: Partial<BashProfileSnapshot> = {}): BashProfileSnapshot {
  return Object.freeze({
    readOnlyBash: false,
    ghApiReadOnly: false,
    ghReadOnly: false,
    helmReadOnly: false,
    strictProfiles: Object.freeze(Object.fromEntries(STRICT_BASH_PROFILE_EXECUTABLES.map(([profile]) => [profile, false]))) as BashProfileSnapshot["strictProfiles"],
    ghPrCreate: Object.freeze({ enabled: false, allowedRepositories: Object.freeze([]), allowedOrganizations: Object.freeze([]) }),
    limits: Object.freeze({ maxFunctionDepth: 128, maxNestedScriptDepth: 64, maxSteps: 7_500, maxWorkItems: 10_000 }),
    ...overrides,
  });
}

function configured(source: string, profiles: BashProfileSnapshot, values: Readonly<Record<string, string>> = {}) {
  return evaluateConfiguredBash({ source, initialEnvironment: { kind: "verified", values }, profileSnapshot: profiles });
}

function ghApi(source: string): string {
  return configured(source, snapshot({ ghApiReadOnly: true }), { GH_PAGER: "" }).permission.kind;
}

function ghPrCreate(source: string, activePolicy: GhPrCreatePolicy = policy): string {
  return configured(source, snapshot({ ghPrCreate: Object.freeze(activePolicy) }), { GH_PROMPT_DISABLED: "1" }).permission.kind;
}

function ghReadOnly(source: string): string {
  return configured(source, snapshot({ ghReadOnly: true })).permission.kind;
}

function helmReadOnly(source: string): string {
  return configured(source, snapshot({ helmReadOnly: true })).permission.kind;
}

function strictReadOnly(source: string, profile: "dockerReadOnly" | "kubectlReadOnly"): string {
  return configured(source, snapshot({
    strictProfiles: Object.freeze({ ...snapshot().strictProfiles, [profile]: true }),
  })).permission.kind;
}

describe("walker-backed gh policy compatibility", () => {
  test("keeps every API denial and makes denial dominate wrapper uncertainty", () => {
    const result = configured(
      "strace -o trace.log gh api user -X POST",
      snapshot({
        ghApiReadOnly: true,
        ghReadOnly: true,
        ghPrCreate: Object.freeze(policy),
      }),
      { GH_PAGER: "", GH_PROMPT_DISABLED: "1" },
    );

    expect(result.profiles.ghPrCreate).toMatchObject({ kind: "deny", profile: "ghPrCreate" });
    expect(result.profiles.ghApiReadOnly).toMatchObject({ kind: "deny", profile: "ghApiReadOnly" });
    expect(result.permission).toMatchObject({ kind: "deny", profile: "ghPrCreate" });
  });

  test("property: opaque shell routes defer every enabled GitHub profile", () => {
    const profiles = snapshot({
      ghApiReadOnly: true,
      ghReadOnly: true,
      ghPrCreate: Object.freeze(policy),
    });
    const staticRoutes = [
      "bash ./create-pr.sh",
      "sh -- ./create-pr.sh",
      "dash ./create-pr.sh",
      "ksh ./create-pr.sh",
      "zsh ./create-pr.sh",
      "fish ./create-pr.fish",
      "source ./create-pr.sh",
      ". ./create-pr.sh",
    ];
    for (const source of staticRoutes) {
      const result = configured(source, profiles, { GH_PAGER: "", GH_PROMPT_DISABLED: "1" });
      expect(result.permission, source).toMatchObject({ kind: "defer" });
      expect(Object.values(result.profiles).every((decision) => decision.kind === "defer"), source).toBeTrue();
    }

    for (const source of ['eval "$SCRIPT"', 'bash -c "$SCRIPT"']) {
      const result = evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot: profiles });
      expect(result.permission, source).toMatchObject({ kind: "defer" });
      expect(Object.values(result.profiles).every((decision) => decision.kind === "defer"), source).toBeTrue();
    }
  });

  test("defers opaque GitHub and script routes without claiming known non-API commands", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    for (const source of [
      "gh create-issue",
      "gh extension exec mutate",
      "./create-pr.sh",
      "python ./create_pr.py",
      "node ./create-pr.js",
    ]) {
      expect(configured(source, apiProfile, { GH_PAGER: "" }).permission.kind, source).toBe("defer");
    }
    expect(configured("gh issue create", apiProfile, { GH_PAGER: "" }).permission.kind).toBe("ignore");
  });

  test("defers inherited configuration and imported Bash function shadowing", () => {
    const dockerProfile = snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, dockerReadOnly: true }),
    });
    const kubectlProfile = snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, kubectlReadOnly: true }),
    });
    const cases = [
      ["docker image ls", dockerProfile, { DOCKER_CONFIG: "/tmp/docker-config" }],
      ["kubectl get pods", kubectlProfile, { KUBECONFIG: "/tmp/kubeconfig" }],
      ["docker image ls", dockerProfile, { "BASH_FUNC_docker%%": "() { credential-canary; }" }],
      ["kubectl get pods", kubectlProfile, { "BASH_FUNC_kubectl%%": "() { credential-canary; }" }],
    ] as const;
    for (const [source, profile, environment] of cases) {
      const result = evaluateConfiguredBash({ source, initialEnvironment: policyInitialEnvironment(environment), profileSnapshot: profile });
      expect(result.permission.kind, source).toBe("defer");
      expect(JSON.stringify(result)).not.toContain("credential-canary");
    }

    const pr = evaluateConfiguredBash({
      source: "gh pr create --repo github.com/acme/widgets --fill",
      initialEnvironment: policyInitialEnvironment({ GH_PROMPT_DISABLED: "1", "BASH_FUNC_gh%%": "() { credential-canary; }" }),
      profileSnapshot: snapshot({ ghPrCreate: Object.freeze(policy) }),
    });
    expect(pr.permission).toMatchObject({ kind: "deny", profile: "ghPrCreate" });
    expect(JSON.stringify(pr)).not.toContain("credential-canary");
  });

  test("keeps allowlisted native PR creation prompt-gated through transparent wrappers", () => {
    expect(ghPrCreate(
      "TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill",
      policy,
    )).toBe("defer");
  });

  test("preserves nested GH denials through builtin eval", () => {
    expect(ghApi("builtin eval 'gh api user -X POST'")).toBe("deny");
    expect(ghApi("builtin -- eval 'gh api user -X POST'")).toBe("deny");
    expect(ghPrCreate("builtin eval 'gh api user -X POST'")).toBe("deny");
    expect(ghPrCreate("builtin eval 'gh pr create --repo github.com/attacker/widgets --fill'")).toBe("deny");
  });

  test("preserves nested GH denials through executable builtin targets", () => {
    expect(ghApi("builtin command gh api user -X POST")).toBe("deny");
    expect(ghApi("builtin -- command -- gh api user -X POST")).toBe("deny");
    expect(ghPrCreate("builtin exec gh api user -X POST")).toBe("deny");
    expect(ghPrCreate("builtin command gh pr create --repo github.com/attacker/widgets --fill")).toBe("deny");
  });

  test("property: builtin eval spellings preserve every mutating API method denial", () => {
    for (const separator of ["", " --"]) {
      for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
        for (const methodFlag of [`-X ${method}`, `--method ${method}`, `--method=${method}`]) {
          const source = `builtin${separator} eval 'gh api user ${methodFlag}'`;
          expect(ghApi(source), source).toBe("deny");
        }
      }
    }
  });

  test("property: builtin command and exec preserve every mutating API method denial", () => {
    for (const target of ["command", "exec"]) {
      for (const delimiter of ["", " --"]) {
        for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
          const source = `builtin ${target}${delimiter} gh api user -X ${method}`;
          expect(ghApi(source), source).toBe("deny");
        }
      }
    }
  });

  test("property: repeated builtin dispatch preserves GitHub mutation denials", () => {
    for (let depth = 1; depth <= 16; depth++) {
      const prefix = "builtin ".repeat(depth);
      expect(ghApi(`${prefix}command gh api user -X POST`)).toBe("deny");
      expect(ghPrCreate(`${prefix}command gh pr create --repo github.com/attacker/widgets --fill`)).toBe("deny");
    }
  });

  test("owns API methods and PR creation flags before their subcommands", () => {
    expect(ghApi("gh -X POST api user")).toBe("deny");
    expect(ghApi("gh --method POST api user")).toBe("deny");
    expect(ghPrCreate("gh -X POST api user")).toBe("deny");
    expect(ghPrCreate("gh pr --title x create --body y --repo github.com/attacker/widgets")).toBe("deny");
    expect(ghPrCreate("gh pr -t x create -b y -Rgithub.com/attacker/widgets")).toBe("deny");
    expect(ghPrCreate("gh pr -df create -Rgithub.com/acme/widgets")).toBe("defer");
    expect(ghPrCreate("gh -t x -b y -Rgithub.com/acme/widgets pr create")).toBe("defer");
  });

  test("property: API method placement cannot change mutation ownership", () => {
    const methods = ["POST", "PUT", "PATCH", "DELETE"];
    const forms = (method: string) => [
      `gh -X ${method} api user`,
      `gh -X${method} api user`,
      `gh -iX${method} api user`,
      `gh --method ${method} api user`,
      `gh --method=${method} api user`,
      `gh api -X ${method} user`,
      `gh api user --method=${method}`,
    ];
    for (const method of methods) for (const source of forms(method)) expect(ghApi(source), source).toBe("deny");
  });

  test("property: GraphQL endpoints are denied for every read method and option ordering", () => {
    const endpoints = ["graphql", "/graphql", "graphql?query=x", "https://api.github.com/graphql"];
    for (const endpoint of endpoints) {
      for (const method of ["GET", "HEAD"]) {
        for (const source of [
          `gh api ${endpoint} -X ${method}`,
          `gh api -X${method} ${endpoint}`,
          `gh -X${method} api ${endpoint}`,
          `gh --method=${method} api ${endpoint}`,
        ]) expect(ghApi(source), source).toBe("deny");
      }
    }
    expect(configured(
      "gh api $ENDPOINT -X GET",
      snapshot({ ghApiReadOnly: true }),
      { GH_PAGER: "", ENDPOINT: "graphql?query=query" },
    ).permission.kind).toBe("deny");
    expect(evaluateConfiguredBash({
      source: 'gh api graphql -X "$METHOD"',
      initialEnvironment: { kind: "unavailable" },
      profileSnapshot: snapshot({ ghApiReadOnly: true }),
    }).permission.kind).toBe("deny");
  });

  test("property: PR flag placement and short clusters preserve repository ownership", () => {
    const repositories = ["github.com/acme/widgets", "github.com/attacker/widgets"];
    const forms = (repository: string) => [
      `gh pr --title x create --body y --repo ${repository}`,
      `gh pr -t x create -b y -R${repository}`,
      `gh pr -df create -R${repository}`,
      `gh -R${repository} pr -df create`,
      `gh -t x -b y -R${repository} pr create`,
    ];
    for (const repository of repositories) {
      for (const source of forms(repository)) {
        expect(ghPrCreate(source), source).toBe(repository.includes("/acme/") ? "defer" : "deny");
      }
    }
  });

  test("requires an explicit host after stateful assignment resolution", () => {
    expect(ghPrCreate(
      "REPO=acme/widgets; gh pr create --repo $REPO --fill",
      policy,
    )).toBe("deny");
  });

  test("defers non-PR gh invocations beside an allowlisted PR creation", () => {
    expect(ghPrCreate(
      "gh pr create --repo github.com/acme/widgets --fill; gh repo delete acme/widgets",
      policy,
    )).toBe("defer");
  });

  test("does not activate unrelated credential-safe profiles", () => {
    expect(ghReadOnly("gh label list; docker image ls")).toBe("defer");
    expect(strictReadOnly("docker image ls; gh label list", "dockerReadOnly")).toBe("defer");
    expect(strictReadOnly("docker image ls; kubectl get pods", "dockerReadOnly")).toBe("defer");
  });

  test("uses an explicit gh api method ahead of parameter-implied POST", () => {
    expect(ghApi("METHOD=GET; gh api -X $METHOD -f q=x user")).toBe("defer");
    expect(ghApi("gh api -f q=x --method=HEAD user")).toBe("defer");
    expect(ghApi("gh api -X GET graphql")).toBe("deny");
  });

  test("defers gh api host, local-input, output, cache, and unknown routes", () => {
    for (const command of [
      "gh api --hostname attacker.example user",
      "gh api user --input body.json -X GET",
      "gh api user --input - -X HEAD",
      "gh api user -F query=@body.txt --method GET",
      "gh api user --field=query=@- --method HEAD",
      "gh api user --cache 1h",
      "gh api user --verbose",
      "gh api user --include",
      "gh api user --header Authorization:value",
      "gh api user --allow-escape-sequences",
      "gh api user --paginate",
      "gh api user --unknown",
      "gh api user extra",
      "gh api https://attacker.example/user",
      "./gh api user",
      "gh api user > response.json",
      "UNRELATED=value gh api user",
    ]) expect(ghApi(command), command).toBe("defer");
  });

  test("property: unsafe gh api options defer at every argument boundary", () => {
    const unsafe = [
      ["--hostname", "attacker.example"], ["--input", "body.json"], ["-H", "Authorization:value"],
      ["--cache", "1h"], ["--verbose"], ["--include"], ["--allow-escape-sequences"], ["--unknown"],
    ];
    const safe = [["-X", "GET"], ["user"]];
    for (const option of unsafe) {
      for (let index = 0; index <= safe.length; index++) {
        const args = [...safe.slice(0, index).flat(), ...option, ...safe.slice(index).flat()];
        expect(ghApi(`gh api ${args.join(" ")}`), args.join(" ")).toBe("defer");
      }
    }
  });

  test("denies explicit mutating gh api methods even beside unsafe options", () => {
    for (const command of [
      "gh api user -X POST",
      "gh api user --input body.json",
      "gh api --hostname attacker.example user --method DELETE",
      "gh api graphql -X PATCH",
      "gh api graphql -f query=mutation",
      "gh api user -X POST --method POST",
      "gh api user --method PUT -X DELETE",
      "bash -lc 'gh api user -X POST'",
      "bash -euo pipefail -c 'gh api user -X POST'",
      "bash -c \"gh api user -X POST\"",
      "bash +O extglob -c 'gh api user -X POST'",
      "bash -coo pipefail nounset 'gh api user -X POST'",
      "bash -Ec 'gh api user -X POST'",
      "bash --debug -c 'gh api user -X POST'",
      "zsh -dfc 'gh api user -X POST'",
      "zsh --no-global-rcs -c 'gh api user -X POST'",
      "zsh +-no-RCS -c 'gh api user -X POST'",
      "exec -cl gh api user -X POST",
      "nice -5 gh api user -X POST",
      "setsid -fw gh api user -X POST",
      "xargs sh -c 'gh api user -X POST'",
      "find . -exec sh -c 'gh api user -X POST' _ {} \\;",
      "eval -- 'gh api user -X POST'",
      "fish -C true -c 'gh api user -X POST'",
      "fish --profile-startup /tmp/profile -c 'gh api user -X POST'",
      "fish --init-cmd true -c 'gh api user -X POST'",
      "fish --private -c 'gh api user -X POST'",
      "fish --interactive -c 'gh api user -X POST'",
      "fish --profile-startup /tmp/profile -c 'gh api user -X POST'",
      "sudo gh api user -X POST",
      "sudo -u root -- gh api user -X DELETE",
      "timeout -vk1s 30s gh api user -X POST",
      "gh api -iXPOST user",
      "gh api -iX POST user",
    ]) expect(ghApi(command), command).toBe("deny");
  });

  test("uses the last repeated method value, matching gh scalar flag parsing", () => {
    expect(ghApi("gh api -X GET --method POST user")).toBe("deny");
    expect(ghApi("gh api --method=GET -XPOST user")).toBe("deny");
    expect(ghApi("gh api -X POST --method GET user")).toBe("defer");
    expect(ghApi("gh api -X GET --method GET user")).toBe("defer");
  });

  test("property: every ordering of repeated mutating methods is denied", () => {
    const methods = ["POST", "PUT", "PATCH", "DELETE"];
    for (const first of methods) {
      for (const second of methods) {
        expect(ghApi(`gh api user -X ${first} --method ${second}`), `${first}/${second}`).toBe("deny");
        expect(ghApi(`gh api --method=${second} -X${first} user`), `${second}/${first}`).toBe("deny");
      }
    }
  });

  test("property: the final repeated method controls mixed read/write requests", () => {
    for (const readMethod of ["GET", "HEAD"]) {
      for (const writeMethod of ["POST", "PUT", "PATCH", "DELETE"]) {
        expect(ghApi(`gh api user -X ${readMethod} -X ${writeMethod}`), `${readMethod}/${writeMethod}`).toBe("deny");
        expect(ghApi(`gh api user -X ${writeMethod} -X ${readMethod}`), `${writeMethod}/${readMethod}`).toBe("defer");
      }
    }
  });

  test("property: include-method shorthand clusters retain mutating method denials", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      expect(ghApi(`gh api -iX${method} user`), method).toBe("deny");
      expect(ghApi(`gh api -iX ${method} user`), method).toBe("deny");
      expect(ghApi(`gh api user -iX${method}`), method).toBe("deny");
    }
  });

  test("does not let a PR option value masquerade as a repository selector", () => {
    expect(ghPrCreate(
      "gh pr create --title --repo=github.com/acme/widgets --fill",
      policy,
    )).toBe("deny");
  });

  test("blocks unknown nested preview commands because they may be configured aliases", () => {
    expect(ghPrCreate("gh preview feature", policy)).toBe("deny");
  });

  test("does not deny quoted gh policy examples that are not executed", () => {
    expect(ghPrCreate(
      "printf '%s' 'gh alias set create-pr pr create'",
      policy,
    )).toBe("ignore");
  });

  test("keeps unknown shell children neutral rather than approving a compound invocation", () => {
    expect(strictReadOnly("docker image ls; unknown-command", "dockerReadOnly")).toBe("defer");
  });

  test("allows a compound invocation only when every command is safe for the active read-only profile", () => {
    expect(strictReadOnly("TOOL=docker; $TOOL image ls; docker volume ls", "dockerReadOnly")).toBe("allow");
  });

  test("migrates gh and helm read-only profiles through assignments and wrappers", () => {
    expect(ghReadOnly("TOOL=gh; strace $TOOL version")).toBe("defer");
    expect(helmReadOnly("TOOL=helm; nice $TOOL version")).toBe("allow");
  });

  test("defers credential-safe profiles after persisted credential configuration bindings", () => {
    expect(strictReadOnly("KUBECONFIG=/tmp/kubeconfig; kubectl get pods", "kubectlReadOnly")).toBe("defer");
    expect(strictReadOnly("DOCKER_CONFIG=/tmp/docker-config; docker image ls", "dockerReadOnly")).toBe("defer");
    expect(ghReadOnly("GH_CONFIG_DIR=/tmp/gh-config; gh label list")).toBe("defer");
  });

  test("preserves credential-safe allows for unrelated persisted bindings", () => {
    expect(strictReadOnly("LABEL=stable; kubectl get pods", "kubectlReadOnly")).toBe("allow");
    expect(strictReadOnly("TOOL=docker; $TOOL image ls", "dockerReadOnly")).toBe("allow");
    expect(ghReadOnly("LABEL=stable; gh version")).toBe("defer");
  });

  test("enforces verified, empty, inherited, unavailable, and shell-overridden gh environment facts", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    const api = "gh api user";
    const pr = "gh pr create --repo github.com/acme/widgets --fill";

    expect(configured(api, apiProfile).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { GH_PAGER: "" }).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { GH_PAGER: "cat" }).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { GH_PAGER: "printf" }).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { PAGER: "printf" }).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { GH_PAGER: "", GH_HOST: "" }).permission.kind).toBe("defer");
    expect(configured(api, apiProfile, { GH_PAGER: "", GH_HOST: "attacker.example" }).permission.kind).toBe("defer");
    expect(configured(pr, prProfile, { GH_PROMPT_DISABLED: "1", GH_PATH: "/tmp/gh" }).permission.kind).toBe("deny");
    expect(configured(api, apiProfile, { GH_TELEMETRY_SAMPLE_RATE: "100" }).permission.kind).toBe("defer");

    expect(evaluateConfiguredBash({ source: api, initialEnvironment: { kind: "unavailable" }, profileSnapshot: apiProfile }).permission.kind).toBe("defer");
    expect(evaluateConfiguredBash({ source: pr, initialEnvironment: { kind: "unavailable" }, profileSnapshot: prProfile }).permission.kind).toBe("deny");
    expect(evaluateConfiguredBash({ source: "gh api \"$ENDPOINT\"", initialEnvironment: { kind: "unavailable" }, profileSnapshot: prProfile }).permission.kind).toBe("deny");
    expect(evaluateConfiguredBash({ source: "gh issue view \"$NUMBER\"", initialEnvironment: { kind: "unavailable" }, profileSnapshot: prProfile }).permission.kind).toBe("ignore");
  });

  test("defers inherited executable and argument variables omitted from the filtered snapshot", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    for (const [source, environment] of [
      ["$RUNNER api user -X POST", { RUNNER: "gh" }],
      ["$SHELL -c 'gh api user -X POST'", { SHELL: "/bin/bash" }],
      ["gh api user -X $METHOD", { METHOD: "POST", GH_PAGER: "" }],
    ] as const) {
      const result = evaluateConfiguredBash({
        source,
        initialEnvironment: policyInitialEnvironment(environment),
        profileSnapshot: apiProfile,
      });
      expect(result.permission.kind, source).toBe("defer");
    }
  });

  test("retains GH ownership when pre-subcommand flags contain unresolved values", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    expect(evaluateConfiguredBash({
      source: 'gh -X POST api "$ENDPOINT"',
      initialEnvironment: policyInitialEnvironment({ GH_PAGER: "" }),
      profileSnapshot: apiProfile,
    }).permission.kind).toBe("deny");
    expect(evaluateConfiguredBash({
      source: 'gh -X "$METHOD" api user',
      initialEnvironment: policyInitialEnvironment({ GH_PAGER: "" }),
      profileSnapshot: apiProfile,
    }).permission.kind).toBe("defer");
    expect(evaluateConfiguredBash({
      source: 'gh pr -t "$TITLE" create -b y -Rgithub.com/attacker/widgets',
      initialEnvironment: policyInitialEnvironment({ GH_PROMPT_DISABLED: "1" }),
      profileSnapshot: prProfile,
    }).permission.kind).toBe("deny");
  });

  test("property: unresolved values cannot erase known GH ownership", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    const environment = policyInitialEnvironment({ GH_PAGER: "", GH_PROMPT_DISABLED: "1" });
    for (const source of [
      'gh -X POST api "$ENDPOINT"',
      'gh --method POST api "$ENDPOINT"',
      'gh -H "$HEADER" -X POST api user',
      'gh "$COMMAND" user',
    ]) {
      expect(evaluateConfiguredBash({ source, initialEnvironment: environment, profileSnapshot: apiProfile }).permission.kind, source)
        .not.toBe("ignore");
    }
    for (const source of [
      'gh pr -t "$TITLE" create -b y -Rgithub.com/attacker/widgets',
      'gh -t "$TITLE" pr create -b y -Rgithub.com/attacker/widgets',
      'gh pr -df create -R"$REPOSITORY"',
    ]) {
      expect(evaluateConfiguredBash({ source, initialEnvironment: environment, profileSnapshot: prProfile }).permission.kind, source)
        .toBe("deny");
    }
  });

  test("shell startup inputs hard-block protected paths and defer executable startup routes", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    for (const source of [
      "bash --noprofile --rcfile credentials.json -ic true",
      "bash --init-file credentials.json -ic true",
      "BASH_ENV=credentials.json bash -c true",
    ]) expect(evaluateBashGuards({ source }), source).toMatchObject({ kind: "block", policy: { name: "secret-read", decision: "deny" } });

    for (const [source, environment] of [
      ["bash --rcfile setup.sh -ic true", policyInitialEnvironment({})],
      ["bash -c true", policyInitialEnvironment({ BASH_ENV: "setup.sh" })],
      ["sh -c true", policyInitialEnvironment({ ENV: "setup.sh" })],
      ["zsh -c true", policyInitialEnvironment({ ZDOTDIR: "/tmp/zsh" })],
    ] as const) {
      expect(evaluateConfiguredBash({ source, initialEnvironment: environment, profileSnapshot: apiProfile }).permission.kind, source)
        .toBe("defer");
    }
  });

  test("property: shell startup-file spellings preserve hard blocks and profile deferral", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    for (const path of ["credentials.json", ".env", "id_rsa"]) {
      for (const source of [
        `bash --rcfile ${path} -ic true`,
        `bash --rcfile=${path} -ic true`,
        `bash --init-file ${path} -ic true`,
        `BASH_ENV=${path} bash -c true`,
      ]) expect(evaluateBashGuards({ source }), source).toMatchObject({ kind: "block", policy: { name: "secret-read", decision: "deny" } });
    }
    for (let index = 0; index < 64; index++) {
      const path = `startup-${index}.sh`;
      const source = index % 2 === 0 ? `bash --rcfile=${path} -ic true` : `bash --init-file ${path} -ic true`;
      expect(evaluateConfiguredBash({ source, initialEnvironment: policyInitialEnvironment({}), profileSnapshot: apiProfile }).permission.kind, source)
        .toBe("defer");
    }
  });

  test("property: filtered inherited variables never become known-unset authorization facts", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    for (let index = 0; index < 64; index++) {
      const name = `SAFETY_CORE_RUNNER_${index}`;
      const initialEnvironment = policyInitialEnvironment({ [name]: `credential-canary-${index}` });
      const result = evaluateConfiguredBash({
        source: `$${name} api user -X POST`,
        initialEnvironment,
        profileSnapshot: apiProfile,
      });
      expect(result.permission.kind, name).toBe("defer");
      expect(JSON.stringify(initialEnvironment)).not.toContain(`credential-canary-${index}`);
    }
  });

  test("rejects unexported pager and prompt-disable proof variables", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    const pr = "gh pr create --repo github.com/acme/widgets --fill";

    expect(configured("GH_PAGER=; gh api user", apiProfile).permission.kind).toBe("defer");
    expect(configured("GH_PAGER=cat; gh api user", apiProfile).permission.kind).toBe("defer");
    expect(configured(`GH_PROMPT_DISABLED=1; ${pr}`, prProfile).permission.kind).toBe("deny");
  });

  test("property: every accepted gh proof value requires process export", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    const pr = "gh pr create --repo github.com/acme/widgets --fill";

    for (const value of ["", "cat"]) {
      expect(configured(`GH_PAGER=${value}; gh api user`, apiProfile).permission.kind, `unexported pager ${value}`).toBe("defer");
      expect(configured(`export GH_PAGER=${value}; gh api user`, apiProfile).permission.kind, `exported pager ${value}`).toBe("defer");
      expect(configured(`GH_PAGER=${value} gh api user`, apiProfile).permission.kind, `prefix pager ${value}`).toBe("defer");
    }
    for (const value of ["", "0", "1", "false"]) {
      expect(configured(`GH_PROMPT_DISABLED=${value}; ${pr}`, prProfile).permission.kind, `unexported prompt ${value}`).toBe("deny");
      expect(configured(`export GH_PROMPT_DISABLED=${value}; ${pr}`, prProfile).permission.kind, `exported prompt ${value}`).toBe("defer");
      expect(configured(`GH_PROMPT_DISABLED=${value} ${pr}`, prProfile).permission.kind, `prefix prompt ${value}`).toBe("defer");
    }
  });

  test("property: every applicable non-empty gh environment route prevents ownership approval", () => {
    const apiProfile = snapshot({ ghApiReadOnly: true });
    const prProfile = snapshot({ ghPrCreate: Object.freeze(policy) });
    for (const name of GH_API_DEFER_ENVIRONMENT_NAMES) {
      expect(configured("gh api user", apiProfile, { GH_PAGER: "", [name]: "policy-test" }).permission.kind, name).toBe("defer");
      expect(configured("gh api user", apiProfile, { GH_PAGER: "", [name]: "" }).permission.kind, `${name} empty`).toBe("defer");
    }
    for (const name of GH_GLOBAL_DEFER_ENVIRONMENT_NAMES) {
      expect(configured("gh pr create --repo github.com/acme/widgets --fill", prProfile, { GH_PROMPT_DISABLED: "1", [name]: "policy-test" }).permission.kind, name).toBe("deny");
      expect(configured("gh pr create --repo github.com/acme/widgets --fill", prProfile, { GH_PROMPT_DISABLED: "1", [name]: "" }).permission.kind, `${name} empty`).toBe("defer");
    }
  });

  test("property: gh api explicit method precedence survives every audited flag position through a wrapper", () => {
    const blocks = [["-f", "q=x"], ["user"]];
    for (let index = 0; index <= blocks.length; index++) {
      const args = [...blocks.slice(0, index).flat(), "-X", "GET", ...blocks.slice(index).flat()];
      expect(ghApi(`strace gh api ${args.join(" ")}`), args.join(" ")).toBe("defer");
    }
  });

  test("property: 64 generated repository flag positions through a transparent wrapper preserve the allowlist decision", () => {
    const positions = [
      ["--repo", "github.com/acme/widgets", "pr", "create", "--fill"],
      ["pr", "--repo", "github.com/acme/widgets", "create", "--fill"],
      ["pr", "create", "--repo", "github.com/acme/widgets", "--fill"],
      ["pr", "create", "--fill", "--repo=github.com/acme/widgets"],
    ];
    let state = 0x4d595df4;
    for (let index = 0; index < 64; index++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const args = positions[state % positions.length]!;
      expect(ghPrCreate(`strace gh ${args.join(" ")}`, policy)).toBe("defer");
    }
  });

  test("property: generated PR option ownership through wrappers never converts option values into repository flags", () => {
    const titleForms = ["--title", "-t", "--body", "-b"];
    for (let index = 0; index < 64; index++) {
      const title = titleForms[index % titleForms.length]!;
      expect(ghPrCreate(
        `strace gh pr create ${title} --repo=github.com/acme/widgets --fill`,
        policy,
      )).toBe("deny");
    }
  });

  test("property: repeated method forms stay deferred through transparent wrappers", () => {
    const first = ["-X", "--method", "-X=", "--method="];
    const second = ["-X", "--method", "-X=", "--method="];
    for (const left of first) {
      for (const right of second) {
        const render = (flag: string, method: string): string[] => flag.endsWith("=") ? [`${flag}${method}`] : [flag, method];
        const args = [...render(left, "GET"), ...render(right, "GET"), "user"];
        expect(ghApi(`strace gh api ${args.join(" ")}`), args.join(" ")).toBe("defer");
      }
    }
  });

  test("property: common gh startup forms compose only to a defer", () => {
    const ghReads = ["gh --version", "gh version", "gh help environment"];
    for (const left of ghReads) {
      for (const right of ghReads) expect(ghReadOnly(`${left}; ${right}`)).toBe("defer");
    }
  });

  test("keeps ordinary unresolved execution neutral in the generic analysis API", () => {
    expect(evaluateBashGuards({ source: "$UNKNOWN image ls" })).toMatchObject({ kind: "pass", status: "indeterminate" });
  });

  test("keeps raw PR authorization neutral until every reachable command is safe", () => {
    expect(ghPrCreate("gh pr create --repo github.com/acme/widgets --fill", policy)).toBe("defer");
    expect(ghPrCreate("gh pr create --repo github.com/acme/widgets --fill; $UNKNOWN", policy)).toBe("defer");
    expect(ghPrCreate("$UNKNOWN; gh pr create --repo github.com/attacker/widgets --fill", policy)).toBe("deny");
  });

  test("raw PR adapter analysis does not auto-allow unrelated base-handler reads", () => {
    expect(ghPrCreate("cat README.md", policy)).toBe("ignore");
  });
});
