import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const pipeline = readFileSync(resolve(root, ".tekton/ci.yaml"), "utf8");
const preCommit = readFileSync(resolve(root, ".pre-commit-config.yaml"), "utf8");

const configuredHookIds = [...preCommit.matchAll(/^\s+- id: ([\w-]+)$/gm)].map((match) => match[1]!);
const matrixHookIds = [...pipeline.matchAll(/^          - ([\w-]+)$/gm)].map((match) => match[1]!);

describe("Tekton lint pipeline", () => {
  test("runs every configured pre-commit hook in its parallel matrix", () => {
    expect(matrixHookIds).toEqual(configuredHookIds);
    expect(new Set(matrixHookIds).size).toBe(matrixHookIds.length);
  });

  test("reports the pending and terminal Forgejo status for each lint", () => {
    expect(pipeline).toContain("/api/v1/repos/$(params.repo-owner)/$(params.repo-name)/statuses/$(params.revision)");
    expect(pipeline).not.toContain("api.github.com");
    expect(pipeline).toContain("Authorization: token $FORGEJO_TOKEN");
    expect(pipeline).toContain('post_status pending "Running $lint_id"');
    expect(pipeline).toContain('post_status success "Passed $lint_id"');
    expect(pipeline).toContain('post_status failure "Failed $lint_id"');
    expect(pipeline).toContain('post_status error "Could not run $lint_id"');
    expect(pipeline).toContain('post_status success "Skipped: no matching files"');
    expect(pipeline).toContain('\\"context\\":\\"lint/$lint_id\\"');
  });

  test("property: every matrix context remains unique for arbitrary hook order", () => {
    for (let seed = 0; seed < 1_024; seed++) {
      const ordered = [...matrixHookIds].sort(
        (left, right) => ((left.length * 31 + seed) % 17) - ((right.length * 31 + seed) % 17),
      );
      const contexts = ordered.map((id) => `lint/${id}`);
      expect(new Set(contexts).size, `seed ${seed}`).toBe(matrixHookIds.length);
    }
  });
});
