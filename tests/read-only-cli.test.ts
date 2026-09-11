import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeGhReadOnlyCommand, analyzeHelmReadOnlyCommand, analyzeStrictReadOnlyCommand, initBashParser } from "../src/index.ts";

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

describe("gh read-only profile", () => {
  test("allows credential-safe metadata subcommands without flags", () => {
    for (const command of [
      "gh --help", "gh help issue", "gh completion zsh", "gh licenses", "gh status", "gh auth status",
      "gh alias ls", "gh cache list", "gh ext search foo", "gh gpg-key ls", "gh label list",
      "gh org list", "gh project field-list 1", "gh repo view", "gh rs check", "gh search repos safety",
      "gh ssh-key ls", "gh workflow view build",
    ]) expect(gh(command), command).toBe("allow");
  });

  test("defers flags and commands that can expose credentials or remote content", () => {
    for (const command of [
      "gh auth token", "gh auth status --show-token", "gh auth status -at", "gh auth status --show-token=false",
      "gh issue list --web", "gh pr view -w", "gh repo read-file README --output copy", "gh release download v1",
      "gh run download 1", "gh attestation download artifact", "gh variable get TOKEN",
      "gh issue list", "gh pr diff", "gh gist view example", "gh repo read-file README", "gh secret list",
      "gh search repos safety --limit 10", "gh repo autolink create",
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

  test("property: a supported command never permits an injected shell operator", () => {
    const commands = ["gh issue list", "gh repo view", "gh pr diff", "gh --version"];
    const operators = ["; id", " && id", " | sh", " > output", " $(id)", " 'quoted'"];
    for (const command of commands) for (const operator of operators) expect(gh(`${command}${operator}`)).toBe("defer");
  });
});

describe("helm read-only profile", () => {
  test("allows credential-safe inspection and validation commands without flags", () => {
    for (const command of [
      "helm --help", "helm help upgrade", "helm completion bash", "helm env", "helm lint chart",
      "helm repo list", "helm search hub nginx", "helm search repo nginx", "helm show values chart",
      "helm verify chart", "helm version",
    ]) expect(helm(command), command).toBe("allow");
  });

  test("defers flags and commands that alter state or can expose release content", () => {
    for (const command of [
      "helm install release chart", "helm upgrade release chart", "helm uninstall release", "helm rollback release 1",
      "helm repo add stable url", "helm repo update", "helm dependency build chart", "helm pull chart", "helm package chart",
      "helm plugin install url", "helm registry login registry", "helm test release", "helm get values release > values.yaml",
      "helm get values release", "helm list", "helm template release chart", "helm show values chart --output json",
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
      ["argocd", "argocd app list"], ["cosign", "cosign verify image"],
      ["crane", "crane manifest image"], ["docker", "docker container ls"],
      ["jf", "jf config show server"], ["jfrog", "jfrog rt search artifact"],
      ["kubectl", "kubectl get pods"], ["nix", "nix hash file input"],
      ["nix-env", "nix-env version"], ["nix-store", "nix-store version"],
      ["oc", "oc projects"], ["podman", "podman system connection list"],
      ["podman-compose", "podman-compose ps"], ["skopeo", "skopeo inspect image"],
      ["tofu", "tofu validate"], ["npm", "npm view package"], ["pip", "pip list"],
      ["uv", "uv pip tree"], ["yarn", "yarn workspaces list"],
    ] as const) expect(strict(command, executable), command).toBe("allow");
  });

  test("defers credentials, writes, unreviewed flags, protected resources, and unknown commands", () => {
    for (const [executable, command] of [
      ["argocd", "argocd app get app --auth-token token"], ["cosign", "cosign verify image --output-file result"],
      ["crane", "crane auth token registry"], ["docker", "docker inspect container"],
      ["jf", "jf config export"], ["kubectl", "kubectl get secret"], ["kubectl", "kubectl get serviceaccounts"],
      ["nix", "nix eval --expr expression"], ["nix-env", "nix-env --install package"],
      ["nix-store", "nix-store --realise path"], ["nix-store", "nix-store --query path"], ["oc", "oc whoami --show-token"],
      ["podman", "podman secret inspect value --showsecret"], ["podman", "podman top container -eo args"], ["podman-compose", "podman-compose up"],
      ["skopeo", "skopeo inspect image --creds user:password"], ["tofu", "tofu plan"],
      ["npm", "npm config list"], ["npm", "npm version patch"], ["pip", "pip config list"], ["uv", "uv auth token"],
      ["yarn", "yarn exec command"], ["yarn", "yarn version 1.2.3"], ["docker", "docker ps credentials.json"],
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
});
