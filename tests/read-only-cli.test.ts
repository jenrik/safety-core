import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { analyzeGhReadOnlyCommand, analyzeHelmReadOnlyCommand, initBashParser } from "../src/index.ts";

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

describe("gh read-only profile", () => {
  test("allows documented read-only subcommands and aliases", () => {
    for (const command of [
      "gh --help", "gh help issue", "gh completion zsh", "gh licenses", "gh auth status",
      "gh alias ls", "gh agent-task view 12", "gh at verify artifact", "gh cache list",
      "gh cs logs", "gh discussion view 12", "gh ext search foo", "gh gist list", "gh gpg-key ls",
      "gh issue status", "gh label list", "gh org list", "gh pr diff", "gh project field-list 1",
      "gh release verify-asset v1 asset", "gh repo autolink list", "gh repo deploy-key ls",
      "gh repo gitignore view Go", "gh repo license view mit", "gh repo read-dir path", "gh rs check",
      "gh run watch 1", "gh search repos safety", "gh secret list", "gh skills search gh", "gh ssh-key ls",
      "gh variable list", "gh workflow view build", "gh browse --no-browser", "gh issue develop --list",
      "gh repo set-default --view", "gh cs ssh --config", "gh extensions upgrade --dry-run", "gh skill update --dry-run",
    ]) expect(gh(command)).toBe("allow");
  });

  test("defers credential, browser, download, and write-capable gh forms", () => {
    for (const command of [
      "gh auth token", "gh auth status --show-token", "gh auth status -at", "gh auth status --show-token=false",
      "gh issue list --web", "gh pr view -w", "gh repo read-file README --output copy", "gh release download v1",
      "gh run download 1", "gh attestation download artifact", "gh variable get TOKEN",
      "gh browse --no-browser=false", "gh browse --no-browser --repo acme/widgets", "gh issue develop --list --name branch",
      "gh repo set-default --view --repo acme/widgets", "gh cs ssh --config --command whoami", "gh ext upgrade --dry-run extension",
      "gh codespace ports forward 8080:80", "gh cs ports visibility 8080:public", "gh repo autolink create",
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
  test("allows documented inspection, rendering, and validation commands", () => {
    for (const command of [
      "helm --help", "helm help upgrade", "helm completion bash", "helm dependency list chart", "helm env",
      "helm get values release", "helm history release", "helm lint chart", "helm list", "helm plugin list",
      "helm repo list", "helm search hub nginx", "helm search repo nginx", "helm show values chart",
      "helm status release", "helm template release chart", "helm verify chart", "helm version",
    ]) expect(helm(command), command).toBe("allow");
  });

  test("defers commands that alter clusters, repositories, or the local filesystem", () => {
    for (const command of [
      "helm install release chart", "helm upgrade release chart", "helm uninstall release", "helm rollback release 1",
      "helm repo add stable url", "helm repo update", "helm dependency build chart", "helm pull chart", "helm package chart",
      "helm plugin install url", "helm registry login registry", "helm test release", "helm get values release > values.yaml",
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
