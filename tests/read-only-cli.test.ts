import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  STRICT_BASH_PROFILE_EXECUTABLES,
  evaluateConfiguredBash,
  initBashParser,
  type BashProfileSnapshot,
} from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-read-only-cli-"));

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(
    existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"),
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

function configured(source: string, profileSnapshot: BashProfileSnapshot) {
  return evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot });
}

function gh(command: string): string {
  return configured(command, snapshot({ ghReadOnly: true })).permission.kind;
}

function helm(command: string): string {
  return configured(command, snapshot({ helmReadOnly: true })).permission.kind;
}

function generic(command: string): string {
  return configured(command, snapshot({ readOnlyBash: true })).permission.kind;
}

function genericWithEnvironment(command: string, values: Readonly<Record<string, string>>): string {
  return evaluateConfiguredBash({
    source: command,
    initialEnvironment: { kind: "verified", values },
    profileSnapshot: snapshot({ readOnlyBash: true }),
  }).permission.kind;
}

function strict(command: string, executable: string): string {
  const profile = STRICT_BASH_PROFILE_EXECUTABLES.find(([, candidate]) => candidate === executable)?.[0];
  if (!profile) throw new Error(`No strict profile for ${executable}`);
  return configured(command, snapshot({
    strictProfiles: Object.freeze({ ...snapshot().strictProfiles, [profile]: true }),
  })).permission.kind;
}

function insertBlock(blocks: readonly (readonly string[])[], block: readonly string[]): string[][] {
  return Array.from({ length: blocks.length + 1 }, (_, index) => [
    ...blocks.slice(0, index), block, ...blocks.slice(index),
  ].flat());
}

describe("gh read-only profile", () => {
  test("allows credential-safe metadata subcommands without flags", () => {
    for (const command of [
      "gh --help", "gh help issue", "gh completion zsh", "gh licenses", "gh status", "gh auth status",
      "gh cache list", "gh ext search foo", "gh gpg-key ls", "gh label list",
      "gh org list", "gh project field-list 1", "gh repo list", "gh rs check", "gh search repos safety",
      "gh ssh-key ls", "gh workflow view build", "gh -R acme/widgets label list",
      "gh label --repo acme/widgets list", "gh label list --repo=acme/widgets",
    ]) expect(gh(command), command).toBe("allow");
  });

  test("defers flags and commands that can expose credentials or remote content", () => {
    for (const command of [
      "gh auth token", "gh auth status --show-token", "gh auth status -at", "gh auth status --show-token=false",
      "gh issue list --web", "gh pr view -w", "gh repo read-file README --output copy", "gh release download v1",
      "gh run download 1", "gh attestation download artifact", "gh variable get TOKEN",
      "gh issue list", "gh pr diff", "gh gist view example", "gh repo read-file README", "gh secret list",
      "gh repo view acme/widgets", "gh search code password", "gh search repos safety --limit 10",
      "gh repo autolink create", "gh alias list", "gh alias ls", "gh workflow view credentials.json",
    ]) expect(gh(command)).toBe("defer");
  });

  test("leaves gh api to its dedicated profile", () => {
    expect(gh("gh api user")).toBe("ignore");
  });

  test("defers shell syntax and compound commands rather than overriding their permission", () => {
    for (const command of [
      "gh issue list; rm -rf generated", "gh --version > version.txt", "gh --version $(whoami)",
      "gh --version; sh -c 'id' --help", "gh issue list && gh repo delete acme/widgets", "g''h issue list",
    ]) expect(gh(command)).toBe("defer");
  });

  test("defers explicit executable paths while allowing statically resolved assignments", () => {
    for (const command of [
      "./gh label list", "/usr/bin/gh label list",
    ]) expect(gh(command), command).toBe("defer");
    for (const command of ["TOOL=gh; $TOOL label list", "TOOL=gh; strace $TOOL label list"]) {
      expect(gh(command), command).toBe("allow");
    }
  });

  test("property: the repository selector may appear at every argument boundary", () => {
    for (const flag of [["-R", "acme/widgets"], ["-Racme/widgets"], ["--repo=acme/widgets"]]) {
      for (const args of insertBlock([["label"], ["list"]], flag)) {
        expect(gh(["gh", ...args].join(" "))).toBe("allow");
      }
    }
  });

  test("property: a supported command never permits an injected shell operator", () => {
    const commands = ["gh label list", "gh repo list", "gh pr diff", "gh --version"];
    const operators = ["; id", " && id", " | sh", " > output", " $(id)", " 'quoted'"];
    for (const command of commands) for (const operator of operators) expect(gh(`${command}${operator}`), `${command}${operator}`).toBe("defer");
  });
});

describe("helm read-only profile", () => {
  test("allows credential-safe inspection and validation commands without flags", () => {
    for (const command of [
      "helm --help", "helm help upgrade", "helm completion bash",
      "helm search hub nginx", "helm search repo nginx",
      "helm show chart example", "helm inspect chart example", "helm verify chart", "helm version",
    ]) expect(helm(command), command).toBe("allow");
  });

  test("defers flags and commands that alter state or can expose release content", () => {
    for (const command of [
      "helm install release chart", "helm upgrade release chart", "helm uninstall release", "helm rollback release 1",
      "helm repo add stable url", "helm repo update", "helm dependency build chart", "helm pull chart", "helm package chart",
      "helm plugin install url", "helm registry login registry", "helm test release", "helm get values release > values.yaml",
      "helm get values release", "helm list", "helm template release chart", "helm show values chart --output json",
      "helm env", "helm repo list", "helm repo ls", "helm show values chart", "./helm repo list",
      "HELM_KUBETOKEN=value helm env",
      "helm show readme chart", "helm show crds chart", "helm lint credentials.json",
      "helm lint chart", "helm verify private.key", "helm show readme credentials.json",
      "helm template release chart --dependency-update", "helm template release chart --output-dir rendered",
      "helm template release chart --post-renderer ./rewrite.sh",
    ]) expect(helm(command)).toBe("defer");
  });

  test("property: Helm shell operators always defer", () => {
    const commands = ["helm list", "helm template release chart", "helm version"];
    const operators = ["; id", " && id", " | sh", " > output", " $(id)", " 'quoted'"];
    for (const command of commands) for (const operator of operators) expect(helm(`${command}${operator}`)).toBe("defer");
  });
});

describe("generic read-only Bash profile", () => {
  test("allows the reviewed Tea help and Git inspection commands", () => {
    for (const command of [
      "tea --help",
      "git show --no-ext-diff --format=fuller HEAD",
      "git show HEAD:credentials.json",
      "git diff --stat origin/main...origin/feature",
      "git diff -- .env",
      "git log --oneline origin/main..HEAD",
      "git ls-files --cached",
      "git branch --show-current",
      "git worktree list",
      "sha256sum README.md",
      "git show --no-ext-diff HEAD | sha256sum && git diff --stat origin/main...origin/feature",
    ]) expect(generic(command), command).toBe("allow");
  });

  test("keeps Tea mutations and Git forms that can explicitly execute, write, or read outside the repository deferred", () => {
    for (const command of [
      "tea pr merge 3 --repo example/project -s merge",
      "tea help",
      "tea --help --repo example/project",
      "git status",
      "git -c alias.show=!id show HEAD",
      "git show --ext-diff HEAD",
      "git show --textconv HEAD",
      "git diff --output patch origin/main...origin/feature",
      "git diff --output=patch origin/main...origin/feature",
      "git diff --no-index README.md credentials.json",
      "sha256sum README.md > digest",
    ]) expect(generic(command), command).toBe("defer");
  });

  test("defers Git reads when an external diff helper is configured by the environment", () => {
    for (const command of [
      "GIT_EXTERNAL_DIFF=/tmp/diff-helper git diff --stat origin/main...origin/feature",
      "export GIT_EXTERNAL_DIFF=/tmp/diff-helper; git diff --stat origin/main...origin/feature",
      "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.external GIT_CONFIG_VALUE_0=/tmp/diff-helper; git diff --stat origin/main...origin/feature",
      "export GIT_PAGER='sh -c false'; git log --oneline HEAD",
    ]) expect(generic(command), command).toBe("defer");
    expect(genericWithEnvironment("git diff --stat origin/main...origin/feature", {
      GIT_EXTERNAL_DIFF: "/tmp/diff-helper",
    })).toBe("defer");
  });

  test("property: strace output forms never preserve a generic read-only allow", () => {
    const prefixes = ["-o trace.log", "-otrace.log", "--output trace.log", "--output=trace.log"];
    for (const prefix of prefixes) {
      for (const flag of ["", "-f ", "-ff "]) {
        const command = `strace ${flag}${prefix} git diff --stat origin/main...origin/feature`;
        expect(generic(command), command).toBe("defer");
      }
    }
  });

  test("property: strace output forms defer every parsed read-only profile", () => {
    const profiles = [
      { command: "gh label list", analyze: gh },
      { command: "helm version", analyze: helm },
      { command: "docker image ls", analyze: (command: string) => strict(command, "docker") },
    ];
    for (const profile of profiles) {
      for (const output of ["-o trace.log", "-otrace.log", "--output trace.log", "--output=trace.log"]) {
        const command = `strace -f ${output} ${profile.command}`;
        expect(profile.analyze(command), command).toBe("defer");
      }
    }
  });

  test("property: strace redirects defer every parsed read-only profile", () => {
    const profiles = [
      { command: "git diff --stat origin/main...origin/feature", analyze: generic },
      { command: "gh label list", analyze: gh },
      { command: "helm version", analyze: helm },
      { command: "docker image ls", analyze: (command: string) => strict(command, "docker") },
    ];
    for (const profile of profiles) {
      for (const redirect of ["> trace.log", "2> trace.log", ">> trace.log", "2>> trace.log"]) {
        const command = `strace -f ${profile.command} ${redirect}`;
        expect(profile.analyze(command), command).toBe("defer");
      }
    }
  });

  test("property: redirects around a strace compound defer every parsed read-only profile", () => {
    const profiles = [
      { command: "git diff --stat origin/main...origin/feature", analyze: generic },
      { command: "gh label list", analyze: gh },
      { command: "helm version", analyze: helm },
      { command: "docker image ls", analyze: (command: string) => strict(command, "docker") },
    ];
    for (const profile of profiles) {
      for (const redirect of ["> trace.log", "2> trace.log", ">> trace.log", "2>> trace.log"]) {
        const command = `(strace -f ${profile.command}) ${redirect}`;
        expect(profile.analyze(command), command).toBe("defer");
      }
    }
  });

  test("property: Git inspection options and revisions may appear in every order", () => {
    const blocks = [["--no-ext-diff"], ["--stat"], ["origin/main...origin/feature"]];
    for (const args of [
      ...insertBlock([blocks[1]!, blocks[2]!], blocks[0]!),
      ...insertBlock([blocks[0]!, blocks[2]!], blocks[1]!),
      ...insertBlock([blocks[0]!, blocks[1]!], blocks[2]!),
    ]) expect(generic(`git diff ${args.join(" ")}`), args.join(" ")).toBe("allow");
  });
});

describe("strict credential-safe CLI profiles", () => {
  test("allows the reviewed read-only subcommands", () => {
    for (const [executable, command] of [
      ["argocd", "argocd app list"], ["argocd", "argocd project list"],
      ["argocd", "argocd project role list example"], ["cosign", "cosign verify image"],
      ["crane", "crane manifest image"],
      ["docker", "docker image list"], ["docker", "docker volume list"],
      ["jf", "jf config show server"], ["jfrog", "jfrog rt search artifact"],
      ["kubectl", "kubectl get pods"], ["kubectl", "kubectl -n default get pods"],
      ["kubectl", "kubectl get pods --context=dev"], ["nix", "nix hash file input"],
      ["nix-env", "nix-env version"], ["nix-store", "nix-store version"],
      ["oc", "oc projects"], ["podman", "podman system connection list"],
      ["podman", "podman network list"], ["podman", "podman pod ps"], ["podman", "podman secret list"],
      ["podman-compose", "podman-compose images"], ["skopeo", "skopeo list-tags docker://registry/image"],
      ["tofu", "tofu version"],
      ["npm", "npm ls package --json"],
      ["npm", "npm find safety-core"], ["npm", "npm why package"], ["npm", "npm la"], ["pip", "pip list"],
      ["uv", "uv pip tree"], ["yarn", "yarn workspaces list"],
    ] as const) expect(strict(command, executable), command).toBe("allow");
  });

  test("defers credentials, writes, unreviewed flags, protected resources, and unknown commands", () => {
    for (const [executable, command] of [
      ["argocd", "argocd app get app --auth-token token"], ["cosign", "cosign env"],
      ["cosign", "cosign verify image --output-file result"],
      ["crane", "crane auth token registry"], ["crane", "crane config image"], ["docker", "docker inspect container"],
      ["docker", "docker ps"], ["docker", "docker container list"], ["docker", "docker container ls"],
      ["docker", "docker container ps"],
      ["jf", "jf config export"], ["kubectl", "kubectl get secret"], ["kubectl", "kubectl get serviceaccounts"],
      ["kubectl", "kubectl get sa"], ["kubectl", "kubectl get sa/default"],
      ["kubectl", "kubectl get serviceaccounts.v1"], ["kubectl", "kubectl get secrets.v1"],
      ["nix", "nix eval --expr expression"], ["nix-env", "nix-env --install package"],
      ["nix-store", "nix-store --realise path"], ["nix-store", "nix-store --query path"], ["oc", "oc whoami --show-token"], ["oc", "oc get sa"],
      ["podman", "podman history image"], ["podman", "podman ps"], ["podman", "podman container list"],
      ["podman", "podman container ls"], ["podman", "podman container ps"],
      ["podman", "podman secret inspect value --showsecret"], ["podman", "podman top container -eo args"],
      ["podman-compose", "podman-compose ps"], ["podman-compose", "podman-compose up"],
      ["skopeo", "skopeo inspect image"], ["skopeo", "skopeo inspect image --creds user:password"],
      ["tofu", "tofu plan"], ["tofu", "tofu graph"], ["tofu", "tofu validate"],
      ["tofu", "tofu providers"], ["tofu", "tofu providers schema -json"],
      ["tofu", "tofu providers lock"], ["tofu", "tofu providers mirror output"],
      ["tofu", "tofu providers schema"], ["tofu", "tofu validate -json"], ["tofu", "tofu providers schema --json"],
      ["npm", "npm config list"], ["npm", "npm version patch"], ["npm", "npm view ."],
      ["npm", "npm info package"], ["npm", "npm show package"], ["npm", "npm v package"],
      ["npm", "npm query :root"], ["pip", "pip config list"], ["uv", "uv auth token"],
      ["uv", "uv tree"], ["yarn", "yarn exec command"], ["yarn", "yarn version 1.2.3"], ["docker", "docker ps credentials.json"],
      ["docker", "./docker image ls"], ["docker", "/usr/bin/docker image ls"],
      ["docker", "LD_PRELOAD=/tmp/instrumentation.so docker image ls"],
      ["npm", "NODE_OPTIONS=--require=./instrumentation.js npm view package"],
    ] as const) expect(strict(command, executable), command).toBe("defer");
  });

  test("property: reviewed profiles never permit shell injection or flags", () => {
    const commands = [
      ["docker", "docker image ls"], ["kubectl", "kubectl get pods"], ["nix", "nix store ping"],
      ["npm", "npm list"], ["uv", "uv tree"], ["yarn", "yarn info package"],
    ] as const;
    const suffixes = ["; id", " && id", " | sh", " > output", " $(id)", " --token value"];
    for (const [executable, command] of commands) {
      for (const suffix of suffixes) expect(strict(`${command}${suffix}`, executable)).toBe("defer");
    }
  });

  test("property: kubectl safe flags may appear in any order and protected resource spellings always defer", () => {
    const namespaceFlags = [["-n", "default"], ["-ndefault"], ["--namespace=default"]] as const;
    const contextFlags = [["--context", "dev"], ["--context=dev"]] as const;
    const outputFlags = [["-o", "jsonpath='{.status.phase}'"], ["-ojsonpath='{.status.phase}'"], ["--output=jsonpath='{.status.phase}'"]] as const;
    for (const namespace of namespaceFlags) {
      for (const context of contextFlags) {
        for (const output of outputFlags) {
          for (const args of [
            [...namespace, ...context, ...output, "get", "pods"],
            ["get", ...namespace, ...context, ...output, "pods"],
            ["get", "pods", ...namespace, ...context, ...output],
            [...context, "get", ...output, "pods", ...namespace],
            [...namespace, "get", "pods", ...output, ...context],
          ]) {
            expect(strict(["kubectl", ...args].join(" "), "kubectl")).toBe("allow");
          }
        }
      }
    }

    const protectedResources = [
      "secret", "secrets", "sa", "serviceaccount", "serviceaccounts", "tokenrequest", "tokenrequests",
    ];
    for (const base of protectedResources) {
      for (const resource of [base, `${base}/name`, `${base}.v1`, `pods,${base}.v1/name`]) {
        expect(strict(`kubectl get ${resource}`, "kubectl"), resource).toBe("defer");
        expect(strict(`oc get ${resource.toUpperCase()}`, "oc"), resource).toBe("defer");
      }

      const multipleResources = `kubectl get pod/example ${base}.v1/name`;
      expect(strict(multipleResources, "kubectl"), multipleResources).toBe("defer");
      const multipleResourcesResult = configured(multipleResources, snapshot({
        strictProfiles: Object.freeze({ ...snapshot().strictProfiles, kubectlReadOnly: true }),
      }));
      expect(multipleResourcesResult.analysis.evidence, multipleResources).toContainEqual(expect.objectContaining({
        name: "kubectl", decision: "defer",
      }));
      expect(multipleResourcesResult.audit.events, multipleResources).toHaveLength(base === "secret" || base === "secrets" ? 1 : 0);

      for (const ambiguous of [
        `kubectl get pod ${base}/name`,
        `kubectl get pod example ${base}/name`,
      ]) {
        expect(strict(ambiguous, "kubectl"), ambiguous).toBe("defer");
        const ambiguousResult = configured(ambiguous, snapshot({
          strictProfiles: Object.freeze({ ...snapshot().strictProfiles, kubectlReadOnly: true }),
        }));
        expect(ambiguousResult.analysis.evidence, ambiguous).toContainEqual(expect.objectContaining({
          name: "kubectl", decision: "defer",
        }));
        expect(ambiguousResult.audit.events, ambiguous).toHaveLength(base === "secret" || base === "secrets" ? 1 : 0);
      }
    }

    expect(strict("kubectl get pod secret", "kubectl")).toBe("allow");
    expect(configured("kubectl get pod secret", snapshot({
      strictProfiles: Object.freeze({ ...snapshot().strictProfiles, kubectlReadOnly: true }),
    })).audit.events).toEqual([{ kind: "kubectl-secret", policy: "kubectl", fields: {
      kubectl_subcommand: "get", resource: "pod", command_length: "kubectl get pod secret".length,
    } }]);
    expect(strict("kubectl get pod/example deployment/app", "kubectl")).toBe("allow");
  });

  test("property: credential-safe Podman and npm aliases preserve the allow decision", () => {
    for (const command of [
      "podman artifact list", "podman artifact ls", "podman network list", "podman network ls",
      "podman pod list", "podman pod ls", "podman pod ps", "podman secret list", "podman secret ls",
      "podman volume list", "podman volume ls",
    ]) expect(strict(command, "podman"), command).toBe("allow");

    for (const command of [
      "npm search safety-core", "npm find safety-core", "npm s safety-core", "npm se safety-core",
      "npm explain package", "npm why package", "npm ls", "npm list", "npm ll", "npm la",
    ]) expect(strict(command, "npm"), command).toBe("allow");
  });

  test("property: container-list aliases that expose configured commands always defer", () => {
    for (const executable of ["docker", "podman"]) {
      for (const suffix of ["ps", "container list", "container ls", "container ps"]) {
        const command = `${executable} ${suffix}`;
        expect(strict(command, executable), command).toBe("defer");
      }
    }
    expect(strict("podman-compose ps", "podman-compose")).toBe("defer");
  });

  test("property: credential-safe Helm and Argo CD command aliases preserve the allow decision", () => {
    for (const command of ["helm show chart example", "helm inspect chart example"]) {
      expect(helm(command), command).toBe("allow");
    }
    for (const command of ["argocd proj list", "argocd project list", "argocd proj role list example", "argocd project role list example"]) {
      expect(strict(command, "argocd"), command).toBe("allow");
    }
  });

  test("property: OpenTofu configuration-aware reads always defer", () => {
    for (const command of [
      "tofu graph", "tofu providers", "tofu providers schema -json",
      "tofu providers lock", "tofu providers mirror output", "tofu validate",
    ]) expect(strict(command, "tofu"), command).toBe("defer");
  });

  test("property: npm json output may appear anywhere and unknown flags always defer", () => {
    for (const args of insertBlock([["ls"], ["package"]], ["--json"])) {
      expect(strict(["npm", ...args].join(" "), "npm")).toBe("allow");
    }
    for (const command of ["kubectl get pods", "npm ls package", "docker image ls"]) {
      const executable = command.split(" ")[0];
      const args = command.split(" ").slice(1).map((token) => [token]);
      for (const withFlag of insertBlock(args, ["--output-file", "result"])) {
        expect(strict([executable, ...withFlag].join(" "), executable)).toBe("defer");
      }
    }
  });

  test("property: explicit paths never preserve an allow decision", () => {
    for (const [executable, args] of [
      ["docker", "image ls"], ["kubectl", "get pods"], ["npm", "view package"],
      ["tofu", "graph"], ["yarn", "info package"],
    ] as const) {
      for (const prefix of [`./${executable}`, `/usr/bin/${executable}`]) {
        expect(strict(`${prefix} ${args}`, executable)).toBe("defer");
      }
    }
  });
});
