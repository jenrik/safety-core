import { describe, expect, test } from "bun:test";

import { analyzeGitReadOnlyInvocation } from "../src/bash/policies/git.ts";
import { GH_INHERITED_PAGER_FACT, policyInitialEnvironment } from "../src/bash/policy-environment.ts";

function decision(...args: string[]): string {
  return analyzeGitReadOnlyInvocation(args).kind;
}

function insertBlock(blocks: readonly (readonly string[])[], block: readonly string[]): string[][] {
  return Array.from({ length: blocks.length + 1 }, (_, index) => [
    ...blocks.slice(0, index), block, ...blocks.slice(index),
  ].flat());
}

describe("Git read-only policy", () => {
  test("captures only reviewed policy environment facts and excludes credentials", () => {
    expect(policyInitialEnvironment({
      GIT_EXTERNAL_DIFF: "/tmp/diff-helper",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "diff.external",
      GIT_CONFIG_VALUE_0: "Authorization: credential-canary",
      GH_PAGER: "/tmp/gh-pager",
      PAGER: "/tmp/shared-pager",
      GH_TOKEN: "never-capture",
      GITHUB_TOKEN: "never-capture",
      HOME: "/home/agent",
      SECRET_TOKEN: "not-exposed",
    })).toEqual({ kind: "verified", values: {
      GIT_EXTERNAL_DIFF: "/tmp/diff-helper",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "diff.external",
      GH_PAGER: "/tmp/gh-pager",
      [GH_INHERITED_PAGER_FACT]: "/tmp/shared-pager",
    } });
  });

  test("property: captures indexed Git config keys but never their values", () => {
    for (let index = 0; index < 64; index++) {
      const key = `GIT_CONFIG_KEY_${index}`;
      const value = `GIT_CONFIG_VALUE_${index}`;
      const environment = policyInitialEnvironment({ [key]: "http.extraHeader", [value]: `credential-canary-${index}` });
      expect(environment).toEqual({ kind: "verified", values: { [key]: "http.extraHeader" } });
    }
  });

  test("redacts inherited GIT_CONFIG_PARAMETERS while retaining its unsafe presence", () => {
    const canary = "http.extraHeader=Authorization:credential-canary";
    const environment = policyInitialEnvironment({ GIT_CONFIG_PARAMETERS: canary });
    expect(environment.kind).toBe("verified");
    if (environment.kind !== "verified") throw new Error("expected verified environment");
    expect(environment.values.GIT_CONFIG_PARAMETERS).not.toBe(canary);
    expect(environment.values.GIT_CONFIG_PARAMETERS).not.toBe("");
  });

  test("property: inherited Git config parameter values are always reduced to one presence fact", () => {
    const captured = new Set<string>();
    for (let index = 0; index < 64; index++) {
      const canary = `http.extraHeader=credential-canary-${index}`;
      const environment = policyInitialEnvironment({ GIT_CONFIG_PARAMETERS: canary });
      if (environment.kind !== "verified") throw new Error("expected verified environment");
      expect(environment.values.GIT_CONFIG_PARAMETERS).not.toContain(canary);
      captured.add(environment.values.GIT_CONFIG_PARAMETERS!);
    }
    expect(captured.size).toBe(1);
  });

  test("allows reviewed object-database inspection commands", () => {
    for (const args of [
      ["--version"], ["version"],
      ["describe", "HEAD"], ["diff", "--stat", "origin/main...origin/feature"],
      ["diff-files", "--name-only"], ["diff-index", "--cached", "HEAD"],
      ["diff-tree", "--no-commit-id", "-r", "HEAD"], ["for-each-ref", "--format=%(refname)"],
       ["log", "--oneline", "HEAD"], ["log", "--show-signature", "HEAD"], ["ls-files", "--cached"], ["ls-tree", "-r", "HEAD"],
      ["merge-base", "HEAD", "origin/main"], ["name-rev", "HEAD"], ["rev-list", "--count", "HEAD"],
       ["rev-parse", "--show-toplevel"], ["show", "HEAD:credentials.json"], ["show", "--show-signature", "HEAD"], ["show-ref", "--heads"],
      ["verify-commit", "HEAD"], ["verify-tag", "v1.0.0"],
    ]) expect(decision(...args), args.join(" ")).toBe("allow");
  });

  test("allows only audited nested inspection forms", () => {
    for (const args of [
      ["branch"], ["branch", "--list"], ["branch", "-l"], ["branch", "--show-current"],
      ["tag"], ["tag", "--list"], ["tag", "-l"], ["worktree", "list"],
      ["submodule", "status"], ["reflog", "show"],
    ]) expect(decision(...args), args.join(" ")).toBe("allow");
  });

  test("defers writes, configuration, network, working-tree searches, and unreviewed forms", () => {
    for (const args of [
      [], ["status"], ["add", "README.md"], ["commit", "-m", "message"], ["switch", "main"],
      ["config", "--get", "user.name"], ["fetch"], ["push"], ["pull"], ["ls-remote", "origin"],
      ["grep", "password"], ["branch", "feature"], ["tag", "v1.0.0"], ["remote"],
      ["worktree", "prune"], ["submodule", "update"], ["reflog", "expire"],
    ]) expect(decision(...args), args.join(" ")).toBe("defer");
  });

  test("property: unsafe options defer every reviewed command at every argument boundary", () => {
    const commands = [
      ["diff", "--stat", "HEAD"], ["log", "--oneline", "HEAD"], ["show", "HEAD"],
      ["diff-tree", "-r", "HEAD"], ["branch", "--show-current"],
    ];
    const unsafeOptions = [["--ext-diff"], ["--ext"], ["--textconv"], ["--textc"], ["--no-index"], ["--output", "patch"], ["--out=patch"], ["--open-files-in-pager=sh"]];
    for (const command of commands) {
      for (const unsafeOption of unsafeOptions) {
        for (const args of insertBlock(command.map((argument) => [argument]), unsafeOption)) {
          expect(decision(...args), args.join(" ")).toBe("defer");
        }
      }
    }
  });
});
