import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeGhReadOnlyCommand,
  analyzeHelmReadOnlyCommand,
  analyzeKubectl,
  analyzeStrictReadOnlyCommand,
  checkBashForKubectlSecret,
  initBashParser,
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

function gh(command: string): string {
  return analyzeGhReadOnlyCommand(command).kind;
}

function helm(command: string): string {
  return analyzeHelmReadOnlyCommand(command).kind;
}

function strict(command: string, executable: string): string {
  return analyzeStrictReadOnlyCommand(command, executable).kind;
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

  test("defers explicit executable paths and environment assignments", () => {
    for (const command of [
      "./gh label list", "/usr/bin/gh label list", "GH_TOKEN=value gh label list", "A=1 B=2 gh label list",
    ]) expect(gh(command), command).toBe("defer");
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
    for (const command of commands) for (const operator of operators) expect(gh(`${command}${operator}`)).toBe("defer");
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
    const suffixes = ["; id", " && id", " | sh", " > output", " $(id)", " --token value", " --output=result"];
    for (const [executable, command] of commands) {
      for (const suffix of suffixes) expect(strict(`${command}${suffix}`, executable)).toBe("defer");
    }
  });

  test("property: kubectl safe flags may appear in any order and protected resource spellings always defer", () => {
    const namespaceFlags = [["-n", "default"], ["-ndefault"], ["--namespace=default"]] as const;
    const contextFlags = [["--context", "dev"], ["--context=dev"]] as const;
    for (const namespace of namespaceFlags) {
      for (const context of contextFlags) {
        for (const args of [
          [...namespace, ...context, "get", "pods"],
          ["get", ...namespace, ...context, "pods"],
          ["get", "pods", ...namespace, ...context],
          [...context, "get", "pods", ...namespace],
          [...namespace, "get", "pods", ...context],
        ]) {
          expect(strict(["kubectl", ...args].join(" "), "kubectl")).toBe("allow");
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
      expect(analyzeKubectl(multipleResources).kind, multipleResources).toBe("defer");
      expect(checkBashForKubectlSecret(multipleResources), multipleResources).not.toBeNull();

      for (const ambiguous of [
        `kubectl get pod ${base}/name`,
        `kubectl get pod example ${base}/name`,
      ]) {
        expect(strict(ambiguous, "kubectl"), ambiguous).toBe("defer");
        expect(analyzeKubectl(ambiguous).kind, ambiguous).toBe("defer");
        expect(checkBashForKubectlSecret(ambiguous), ambiguous).not.toBeNull();
      }
    }

    expect(strict("kubectl get pod secret", "kubectl")).toBe("allow");
    expect(analyzeKubectl("kubectl get pod secret").kind).toBe("allow");
    expect(checkBashForKubectlSecret("kubectl get pod secret")).toBeNull();
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

  test("property: explicit paths and assignments never preserve an allow decision", () => {
    for (const [executable, args] of [
      ["docker", "image ls"], ["kubectl", "get pods"], ["npm", "view package"],
      ["tofu", "graph"], ["yarn", "info package"],
    ] as const) {
      for (const prefix of [`./${executable}`, `/usr/bin/${executable}`, `A=1 ${executable}`, `A=1 B=2 ${executable}`]) {
        expect(strict(`${prefix} ${args}`, executable)).toBe("defer");
      }
    }
  });
});
