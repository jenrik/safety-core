import { describe, expect, test } from "bun:test";

import { analyzeGitReadOnlyInvocation, gitPolicyInitialEnvironment } from "../src/bash/policies/git.ts";

function decision(...args: string[]): string {
  return analyzeGitReadOnlyInvocation(args).kind;
}

function insertBlock(blocks: readonly (readonly string[])[], block: readonly string[]): string[][] {
  return Array.from({ length: blocks.length + 1 }, (_, index) => [
    ...blocks.slice(0, index), block, ...blocks.slice(index),
  ].flat());
}

describe("Git read-only policy", () => {
  test("captures only Git execution-route environment variables", () => {
    expect(gitPolicyInitialEnvironment({
      GIT_EXTERNAL_DIFF: "/tmp/diff-helper",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "diff.external",
      GIT_CONFIG_VALUE_0: "/tmp/diff-helper",
      HOME: "/home/agent",
      SECRET_TOKEN: "not-exposed",
    })).toEqual({ kind: "verified", values: {
      GIT_EXTERNAL_DIFF: "/tmp/diff-helper",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "diff.external",
      GIT_CONFIG_VALUE_0: "/tmp/diff-helper",
    } });
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
