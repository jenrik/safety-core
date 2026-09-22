import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import genericReadOnly from "../policies/code/generic-read-only.policy.ts";
import ghApi from "../policies/code/gh-api.policy.ts";
import ghReadOnly from "../policies/code/gh-read-only.policy.ts";
import { createGhPrCreatePolicy } from "../policies/code/gh-pr-create.policy.ts";
import helmReadOnly from "../policies/code/helm-read-only.policy.ts";
import strictReadOnly from "../policies/code/strict-read-only.policy.ts";
import { renderGhPrCreateCodePolicy } from "../scripts/render-gh-pr-create-code-policy.ts";
import { analyzeBashWithPolicies, initBashParser, type LoadedBashPolicy, type ValidatedBashPolicy } from "../src/index.ts";

const wasmDir = mkdtempSync(join(tmpdir(), "safety-core-policy-code-permissions-"));
const prCreate = createGhPrCreatePolicy({ allowedRepositories: ["acme/widgets"], allowedOrganizations: ["trusted-org"] });
const policies = Object.freeze([
  loaded("/trusted/generic-read-only.policy.mjs", genericReadOnly),
  loaded("/trusted/gh-read-only.policy.mjs", ghReadOnly),
  loaded("/trusted/helm-read-only.policy.mjs", helmReadOnly),
  loaded("/trusted/strict-read-only.policy.mjs", strictReadOnly),
  loaded("/trusted/gh-api.policy.mjs", ghApi),
  loaded("/trusted/gh-pr-create.policy.mjs", prCreate),
]);

beforeAll(async () => {
  mkdirSync(join(wasmDir, "node_modules"), { recursive: true });
  const packagedWasm = join(process.cwd(), "tree-sitter-bash.wasm");
  copyFileSync(existsSync(packagedWasm) ? packagedWasm : join(process.cwd(), "node_modules", "tree-sitter-bash", "tree-sitter-bash.wasm"), join(wasmDir, "tree-sitter-bash.wasm"));
  symlinkSync(join(process.cwd(), "node_modules", "web-tree-sitter"), join(wasmDir, "node_modules", "web-tree-sitter"));
  await initBashParser(wasmDir);
});

afterAll(() => rmSync(wasmDir, { force: true, recursive: true }));

function evaluate(
  source: string,
  values: Readonly<Record<string, string>> = {},
  activePolicies: readonly ValidatedBashPolicy[] = policies,
): ReturnType<typeof analyzeBashWithPolicies> {
  return analyzeBashWithPolicies({ source, policies: activePolicies, initialEnvironment: { kind: "verified", values } });
}

describe("trusted permission code policies", () => {
  test("covers generic Git, Tea, and checksum reads while ignoring foreign executables", () => {
    for (const source of ["tea --help", "git diff --stat HEAD", "sha256sum README.md"]) expect(evaluate(source).decision, source).toBe("allow");
    expect(evaluate("git show --ext-diff HEAD").decision).toBe("defer");
    expect(genericReadOnly.evaluate(evaluate("echo hello").events[0]!)).toEqual({ kind: "ignore" });
  });

  test("covers Helm and every strict executable without broadening either domain", () => {
    for (const source of ["helm version", "docker image ls", "argocd app list", "cosign verify image", "crane manifest image", "jf config show", "jfrog rt search artifact", "kubectl get pods", "nix hash file input", "nix-env version", "nix-store version", "oc projects", "podman image ls", "podman-compose images", "skopeo list-tags image", "tofu version", "npm ls package --json", "pip list", "uv pip tree", "yarn workspaces list"]) {
      expect(evaluate(source).decision, source).toBe("allow");
    }
    expect(evaluate("kubectl get secret app").decision).toBe("defer");
    expect(strictReadOnly.evaluate(evaluate("helm version").events[0]!)).toEqual({ kind: "ignore" });
  });

  test("preserves path-qualified commands, environment routes, wrappers, aliases, and option permutations", () => {
    for (const source of [
      "./git diff HEAD",
      "GIT_EXTERNAL_DIFF=/tmp/helper git diff HEAD",
      "strace -f git diff HEAD",
      "docker image ls --unknown",
      "kubectl --context dev get pods -n default -o json",
    ]) {
      const expected = source.startsWith("kubectl") ? "allow" : "defer";
      expect(evaluate(source).decision, source).toBe(expected);
    }
  });

  test("keeps GitHub ownership separate for gh read-only, gh api, and PR creation", () => {
    expect(evaluate("gh issue list").decision).toBe("defer");
    expect(ghReadOnly.evaluate(evaluate("gh api user", { GH_PAGER: "" }).events[0]!)).toEqual({ kind: "ignore" });
    const withoutPrCreate = policies.filter((policy) => policy.source.canonicalPath !== "/trusted/gh-pr-create.policy.mjs");
    expect(evaluate("gh api user", { GH_PAGER: "" }, withoutPrCreate).decision).toBe("allow");
    expect(evaluate("gh api graphql", { GH_PAGER: "" }, withoutPrCreate).decision).toBe("deny");
    expect(evaluate("gh pr create --repo github.com/acme/widgets --fill", { GH_PROMPT_DISABLED: "1" }).decision).toBe("allow");
    expect(evaluate("gh pr new --repo github.com/attacker/widgets --fill", { GH_PROMPT_DISABLED: "1" }).decision).toBe("deny");
    expect(evaluate("nice gh pr create --repo github.com/acme/widgets --fill", { GH_PROMPT_DISABLED: "1" }).decision).toBe("defer");
    expect(evaluate("gh alias set create-pr 'pr create --repo github.com/acme/widgets'", { GH_PROMPT_DISABLED: "1" }).decision).toBe("deny");
  });

  test("allows mixed-policy compound commands when every invocation has a matching policy", () => {
    expect(evaluate("git diff HEAD; docker image ls").decision).toBe("allow");
    const withoutPrCreate = policies.filter((policy) => policy.source.canonicalPath !== "/trusted/gh-pr-create.policy.mjs");
    expect(evaluate("git diff HEAD; helm version; gh api user", { GH_PAGER: "" }, withoutPrCreate).decision).toBe("allow");
  });

  test("property: allowlist source generation is deterministic, literal, and validates every generated identifier", () => {
    const first = renderGhPrCreateCodePolicy({ allowedRepositories: ["Acme/Widgets"], allowedOrganizations: ["Trusted-Org"] });
    const second = renderGhPrCreateCodePolicy({ allowedRepositories: ["acme/widgets"], allowedOrganizations: ["trusted-org"] });
    const changed = renderGhPrCreateCodePolicy({ allowedRepositories: ["acme/other"], allowedOrganizations: ["trusted-org"] });

    expect(first).toBe(second);
    expect(changed).not.toBe(first);
    expect(digest(changed)).not.toBe(digest(first));
    expect(first).toContain('Object.freeze(["acme/widgets"])');
    expect(first).toContain('Object.freeze(["trusted-org"])');
    expect(first).not.toContain("config");

    for (const malformed of [
      { allowedRepositories: ["acme"], allowedOrganizations: [] },
      { allowedRepositories: ["acme/widgets/extra/more"], allowedOrganizations: [] },
      { allowedRepositories: ["acme/with space"], allowedOrganizations: [] },
      { allowedRepositories: [], allowedOrganizations: ["host/org/extra"] },
      { allowedRepositories: ["acme/widgets", "ACME/WIDGETS"], allowedOrganizations: [] },
    ]) expect(() => renderGhPrCreateCodePolicy(malformed)).toThrow();

    for (let seed = 0; seed < 128; seed++) {
      const owner = `owner${seed}`;
      const repository = `repo${seed}`;
      const source = renderGhPrCreateCodePolicy({ allowedRepositories: [`github.com/${owner}/${repository}`], allowedOrganizations: [] });
      expect(source).toContain(`github.com/${owner}/${repository}`);
      expect(source).not.toContain("process.env");
    }
  });

  test("bundles generated PR policy allowlists without runtime configuration", async () => {
    const entry = join(process.cwd(), "policy-code-generation-test.ts");
    const output = join(wasmDir, "generated-pr-policy.mjs");
    writeFileSync(entry, renderGhPrCreateCodePolicy({ allowedRepositories: ["github.com/acme/widgets"], allowedOrganizations: ["trusted-org"] }));
    try {
      const build = await Bun.build({ entrypoints: [entry], outdir: wasmDir, naming: "generated-pr-policy.mjs", target: "node", format: "esm" });
      expect(build.success).toBeTrue();
      const bundled = readFileSync(output, "utf8");
      expect(bundled).toContain("github.com/acme/widgets");
      expect(bundled).toContain("trusted-org");
      expect(bundled).not.toContain("process.env");
    } finally {
      rmSync(entry, { force: true });
    }
  });
});

function loaded(path: string, definition: Omit<LoadedBashPolicy, "source"> & { readonly apiVersion: 1 }): ValidatedBashPolicy {
  return Object.freeze({ source: Object.freeze({ canonicalPath: path }), layer: definition.layer, select: definition.select, evaluate: definition.evaluate }) as ValidatedBashPolicy;
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
