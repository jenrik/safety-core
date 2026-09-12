import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  analyzeGhApiCommand,
  analyzeGhPrCreateCommand,
  analyzeGhReadOnlyCommand,
  analyzeHelmReadOnlyCommand,
  analyzeStrictReadOnlyCommand,
  analyzeBashAuthorization,
  initBashParser,
  type GhPrCreatePolicy,
} from "../src/index.ts";

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

describe("walker-backed gh policy compatibility", () => {
  test("resolves assignments through transparent wrappers for allowlisted native PR creation", () => {
    expect(analyzeGhPrCreateCommand(
      "TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill",
      policy,
    ).kind).toBe("allow");
  });

  test("requires an explicit host after stateful assignment resolution", () => {
    expect(analyzeGhPrCreateCommand(
      "REPO=acme/widgets; gh pr create --repo $REPO --fill",
      policy,
    ).kind).toBe("deny");
  });

  test("does not treat non-PR gh invocations as safe beside an allowlisted PR creation", () => {
    expect(analyzeGhPrCreateCommand(
      "gh pr create --repo github.com/acme/widgets --fill; gh repo delete acme/widgets",
      policy,
    ).kind).toBe("deny");
  });

  test("does not activate unrelated credential-safe profiles", () => {
    expect(analyzeGhReadOnlyCommand("gh label list; docker image ls").kind).toBe("defer");
    expect(analyzeStrictReadOnlyCommand("docker image ls; gh label list", "docker").kind).toBe("defer");
    expect(analyzeStrictReadOnlyCommand("docker image ls; kubectl get pods", "docker").kind).toBe("defer");
  });

  test("uses an explicit gh api method ahead of parameter-implied POST", () => {
    expect(analyzeGhApiCommand("METHOD=GET; gh api -X $METHOD -f q=x user").kind).toBe("allow");
    expect(analyzeGhApiCommand("gh api -f q=x --method=HEAD user").kind).toBe("allow");
    expect(analyzeGhApiCommand("gh api -X GET graphql").kind).toBe("defer");
  });

  test("defers repeated or conflicting explicit gh api methods", () => {
    for (const command of [
      "gh api -X GET --method POST user",
      "gh api --method=GET -XPOST user",
      "gh api -X GET --method GET user",
    ]) expect(analyzeGhApiCommand(command).kind, command).toBe("defer");
  });

  test("does not let a PR option value masquerade as a repository selector", () => {
    expect(analyzeGhPrCreateCommand(
      "gh pr create --title --repo=github.com/acme/widgets --fill",
      policy,
    ).kind).toBe("deny");
  });

  test("keeps preview recognized as a non-PR gh invocation", () => {
    expect(analyzeGhPrCreateCommand("gh preview feature", policy).kind).toBe("ignore");
  });

  test("does not deny quoted gh policy examples that are not executed", () => {
    expect(analyzeGhPrCreateCommand(
      "printf '%s' 'gh alias set create-pr pr create'",
      policy,
    ).kind).toBe("ignore");
  });

  test("keeps unknown shell children neutral rather than approving a compound invocation", () => {
    expect(analyzeStrictReadOnlyCommand("docker image ls; unknown-command", "docker").kind).toBe("defer");
  });

  test("allows a compound invocation only when every command is safe for the active read-only profile", () => {
    expect(analyzeStrictReadOnlyCommand("TOOL=docker; $TOOL image ls; docker volume ls", "docker").kind).toBe("allow");
  });

  test("migrates gh and helm read-only profiles through assignments and wrappers", () => {
    expect(analyzeGhReadOnlyCommand("TOOL=gh; strace $TOOL label list").kind).toBe("allow");
    expect(analyzeHelmReadOnlyCommand("TOOL=helm; nice $TOOL version").kind).toBe("allow");
  });

  test("defers credential-safe profiles after persisted credential configuration bindings", () => {
    expect(analyzeStrictReadOnlyCommand("KUBECONFIG=/tmp/kubeconfig; kubectl get pods", "kubectl").kind).toBe("defer");
    expect(analyzeStrictReadOnlyCommand("DOCKER_CONFIG=/tmp/docker-config; docker image ls", "docker").kind).toBe("defer");
    expect(analyzeGhReadOnlyCommand("GH_CONFIG_DIR=/tmp/gh-config; gh label list").kind).toBe("defer");
  });

  test("preserves credential-safe allows for unrelated persisted bindings", () => {
    expect(analyzeStrictReadOnlyCommand("LABEL=stable; kubectl get pods", "kubectl").kind).toBe("allow");
    expect(analyzeStrictReadOnlyCommand("TOOL=docker; $TOOL image ls", "docker").kind).toBe("allow");
    expect(analyzeGhReadOnlyCommand("LABEL=stable; gh label list").kind).toBe("allow");
  });

  test("property: gh api explicit method precedence survives every audited flag position through a wrapper", () => {
    const blocks = [["-f", "q=x"], ["user"]];
    for (let index = 0; index <= blocks.length; index++) {
      const args = [...blocks.slice(0, index).flat(), "-X", "GET", ...blocks.slice(index).flat()];
      expect(analyzeGhApiCommand(`strace gh api ${args.join(" ")}`).kind, args.join(" ")).toBe("allow");
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
      expect(analyzeGhPrCreateCommand(`strace gh ${args.join(" ")}`, policy).kind).toBe("allow");
    }
  });

  test("property: generated PR option ownership through wrappers never converts option values into repository flags", () => {
    const titleForms = ["--title", "-t", "--body", "-b"];
    for (let index = 0; index < 64; index++) {
      const title = titleForms[index % titleForms.length]!;
      expect(analyzeGhPrCreateCommand(
        `strace gh pr create ${title} --repo=github.com/acme/widgets --fill`,
        policy,
      ).kind).toBe("deny");
    }
  });

  test("property: repeated method forms stay deferred through transparent wrappers", () => {
    const first = ["-X", "--method", "-X=", "--method="];
    const second = ["-X", "--method", "-X=", "--method="];
    for (const left of first) {
      for (const right of second) {
        const render = (flag: string, method: string): string[] => flag.endsWith("=") ? [`${flag}${method}`] : [flag, method];
        const args = [...render(left, "GET"), ...render(right, "GET"), "user"];
        expect(analyzeGhApiCommand(`strace gh api ${args.join(" ")}`).kind, args.join(" ")).toBe("defer");
      }
    }
  });

  test("property: only same-profile safe prefixes compose to an allow", () => {
    const ghReads = ["gh label list", "gh repo list", "gh auth status"];
    for (const left of ghReads) {
      for (const right of ghReads) expect(analyzeGhReadOnlyCommand(`${left}; ${right}`).kind).toBe("allow");
    }
  });

  test("keeps ordinary unresolved execution neutral in the generic analysis API", () => {
    expect(analyzeBashAuthorization({ source: "$UNKNOWN image ls" }).verdict.kind).toBe("neutral");
  });
});
