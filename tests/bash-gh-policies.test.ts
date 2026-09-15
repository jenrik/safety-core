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

function configured(source: string, profiles: BashProfileSnapshot) {
  return evaluateConfiguredBash({ source, initialEnvironment: { kind: "unavailable" }, profileSnapshot: profiles });
}

function ghApi(source: string): string {
  return configured(source, snapshot({ ghApiReadOnly: true })).permission.kind;
}

function ghPrCreate(source: string, activePolicy: GhPrCreatePolicy = policy): string {
  return configured(source, snapshot({ ghPrCreate: Object.freeze(activePolicy) })).permission.kind;
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
  test("resolves assignments through transparent wrappers for allowlisted native PR creation", () => {
    expect(ghPrCreate(
      "TOOL=gh; strace $TOOL pr create --repo github.com/acme/widgets --fill",
      policy,
    )).toBe("allow");
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
    expect(ghApi("METHOD=GET; gh api -X $METHOD -f q=x user")).toBe("allow");
    expect(ghApi("gh api -f q=x --method=HEAD user")).toBe("allow");
    expect(ghApi("gh api -X GET graphql")).toBe("defer");
  });

  test("defers repeated or conflicting explicit gh api methods", () => {
    for (const command of [
      "gh api -X GET --method POST user",
      "gh api --method=GET -XPOST user",
      "gh api -X GET --method GET user",
    ]) expect(ghApi(command), command).toBe("defer");
  });

  test("does not let a PR option value masquerade as a repository selector", () => {
    expect(ghPrCreate(
      "gh pr create --title --repo=github.com/acme/widgets --fill",
      policy,
    )).toBe("deny");
  });

  test("keeps preview recognized as a non-PR gh invocation", () => {
    expect(ghPrCreate("gh preview feature", policy)).toBe("ignore");
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
    expect(ghReadOnly("TOOL=gh; strace $TOOL label list")).toBe("allow");
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
    expect(ghReadOnly("LABEL=stable; gh label list")).toBe("allow");
  });

  test("property: gh api explicit method precedence survives every audited flag position through a wrapper", () => {
    const blocks = [["-f", "q=x"], ["user"]];
    for (let index = 0; index <= blocks.length; index++) {
      const args = [...blocks.slice(0, index).flat(), "-X", "GET", ...blocks.slice(index).flat()];
      expect(ghApi(`strace gh api ${args.join(" ")}`), args.join(" ")).toBe("allow");
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
      expect(ghPrCreate(`strace gh ${args.join(" ")}`, policy)).toBe("allow");
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

  test("property: only same-profile safe prefixes compose to an allow", () => {
    const ghReads = ["gh label list", "gh repo list", "gh auth status"];
    for (const left of ghReads) {
      for (const right of ghReads) expect(ghReadOnly(`${left}; ${right}`)).toBe("allow");
    }
  });

  test("keeps ordinary unresolved execution neutral in the generic analysis API", () => {
    expect(evaluateBashGuards({ source: "$UNKNOWN image ls" })).toMatchObject({ kind: "pass", status: "indeterminate" });
  });

  test("keeps raw PR authorization neutral until every reachable command is safe", () => {
    expect(ghPrCreate("gh pr create --repo github.com/acme/widgets --fill", policy)).toBe("allow");
    expect(ghPrCreate("gh pr create --repo github.com/acme/widgets --fill; $UNKNOWN", policy)).toBe("defer");
    expect(ghPrCreate("$UNKNOWN; gh pr create --repo github.com/attacker/widgets --fill", policy)).toBe("deny");
  });

  test("raw PR adapter analysis does not auto-allow unrelated base-handler reads", () => {
    expect(ghPrCreate("cat README.md", policy)).toBe("ignore");
  });
});
